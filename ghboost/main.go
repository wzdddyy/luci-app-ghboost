package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"
)

type rotatingFile struct {
	path string
	max  int64
	f    *os.File
	size int64
}

func newRotatingFile(path string, max int64) (*rotatingFile, error) {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		return nil, err
	}
	var size int64
	if st, serr := f.Stat(); serr == nil {
		size = st.Size()
	}
	return &rotatingFile{path: path, max: max, f: f, size: size}, nil
}

func (r *rotatingFile) Write(p []byte) (int, error) {
	if r.max > 0 && r.size+int64(len(p)) > r.max {
		r.rotate()
	}
	n, err := r.f.Write(p)
	r.size += int64(n)
	return n, err
}

func (r *rotatingFile) rotate() {
	_ = r.f.Close()
	_ = os.Remove(r.path + ".1")
	_ = os.Rename(r.path, r.path+".1")
	f, err := os.OpenFile(r.path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		return
	}
	r.f = f
	r.size = 0
}

func logInfo(format string, args ...interface{}) {
	log.Print("[INFO] " + fmt.Sprintf(format, args...))
}

func logWarn(format string, args ...interface{}) {
	log.Print("[WARN] " + fmt.Sprintf(format, args...))
}

func logError(format string, args ...interface{}) {
	log.Print("[ERROR] " + fmt.Sprintf(format, args...))
}

var version = "dev"

const defaultDNS = "https://dns.alidns.com/dns-query,https://doh.pub/dns-query"

func main() {
	listen := flag.String("listen", ":18443", "本地监听端口 (防火墙 REDIRECT 的目标端口)")
	dns := flag.String("dns", defaultDNS,
		"DNS 上游, 逗号分隔; 多个上游**并发**查询并取并集 (不是按顺序回退); "+
			"支持 DoH URL 和本地 ip:port (dnscrypt-proxy/smartdns 的端口, 别填本机 dnsmasq)")
	domains := flag.String("domains", "/usr/share/ghboost/domains.conf", "fake IP -> 域名 映射文件")
	maxConns := flag.Int("max-conns", 128, "并发连接上限, 满了直接拒绝新连接")
	statsFile := flag.String("stats-file", "/tmp/ghboost.status.json", "状态快照文件 (LuCI 读它), 空=不写")
	bestFile := flag.String("best-file", "/tmp/ghboost.best.json", "测速结果持久化文件, 空=不持久化")
	logFile := flag.String("log-file", "", "日志文件路径, 空=只走 stderr (procd 转 syslog); 建议 /tmp 下避免写 eMMC")
	caCert := flag.String("ca-cert", "/etc/ghboost/ghboost-ca.crt", "CA 证书路径, 不存在则自动生成并写入")
	caKey := flag.String("ca-key", "/etc/ghboost/ghboost-ca.key", "CA 私钥路径, 不存在则自动生成并写入")
	showVersion := flag.Bool("version", false, "打印版本后退出")
	flag.Parse()

	if *showVersion {
		fmt.Println("ghboost", version)
		return
	}

	if *logFile != "" {
		rf, err := newRotatingFile(*logFile, 1<<20)
		if err != nil {
			logWarn("无法打开日志文件 %s: %v, 改用 syslog", *logFile, err)
		} else {
			log.SetOutput(rf)
			logInfo("日志写入 %s, 上限 1MB, 超出后转存 .1", *logFile)
		}
	}

	domTable, err := LoadDomains(*domains)
	if err != nil {
		log.Fatal("[ERROR] 加载域名映射失败: ", err)
	}
	if domTable.len() == 0 {
		log.Fatal("[ERROR] 域名映射为空, 检查 ", *domains)
	}

	res, err := newResolver(*dns)
	if err != nil {
		log.Fatal("[ERROR] DNS 上游配置无效: ", err)
	}

	certs, err := NewCertStore(*caCert, *caKey)
	if err != nil {
		logWarn("CA 证书初始化失败: %v, 将回退到明文中转模式 (不稳定)", err)
		certs = nil
	} else {
		logInfo("CA 证书已就绪: %s", *caCert)
	}

	p := NewProxy(ProxyOptions{
		Listen:     *listen,
		DomainFile: *domains,
		MaxConns:   *maxConns,
		BestFile:   *bestFile,
		StatsFile:  *statsFile,
	}, res, domTable, certs)

	if err := p.Start(); err != nil {
		log.Fatal("[ERROR] 启动失败: ", err)
	}
	logInfo("ghboost %s 启动完成, DNS 上游 %s", version, *dns)

	sigCh := make(chan os.Signal, 2)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP)
	for {
		sig := <-sigCh
		if sig == syscall.SIGHUP {
			if err := p.reloadDomains(); err != nil {
				logError("SIGHUP: 域名映射重载失败: %v", err)
			}
			continue
		}
		logInfo("服务正在停止...")
		break
	}

	p.Stop()
}
