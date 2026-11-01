package main

import (
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"math/rand"
	"net"
	"net/url"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

const (
	dialTimeout = 5 * time.Second
	dialRounds  = 3
	dialBudget = 20 * time.Second
	dialPause  = 300 * time.Millisecond

	relayIdle = 300 * time.Second
	relayFirstByte = 1500 * time.Millisecond
	failPenalty = 1 * time.Minute

	warmupProbeCount = 8
	warmupPort       = "443"
	warmupConcurrency = 16
	warmupSkipFail    = 10 * time.Minute

	probeTimeout  = 3 * time.Second
	probeCooldown = 3 * time.Minute

	dialFastBudget = 4 * time.Second

	expandCooldown  = 2 * time.Minute
	expandPerPrefix = 4
	expandTimeout   = 2 * time.Second
	dynamicExtraMax = 16
)

var ghPrefixes = []string{
	"20.205.243.", "20.200.245.", "20.27.177.", "20.233.83.", "20.250.119.",
	"140.82.112.", "140.82.113.", "140.82.114.", "140.82.116.",
	"4.237.22.",
	"185.199.108.", "185.199.109.", "185.199.110.", "185.199.111.",
}

type bufferedConn struct {
	net.Conn
	buf []byte
}

func newBufferedConn(c net.Conn) *bufferedConn {
	return &bufferedConn{Conn: c}
}

func (b *bufferedConn) Peek(n int) ([]byte, error) {
	if len(b.buf) >= n {
		return b.buf[:n], nil
	}
	need := n - len(b.buf)
	tmp := make([]byte, need)
	m, err := io.ReadFull(b.Conn, tmp)
	if m > 0 {
		b.buf = append(b.buf, tmp[:m]...)
	}
	if err != nil && len(b.buf) < n {
		return b.buf, err
	}
	return b.buf[:n], nil
}

func (b *bufferedConn) prefetch(max int, timeout time.Duration) []byte {
	if len(b.buf) >= 12 {
		return b.buf
	}
	_ = b.Conn.SetReadDeadline(time.Now().Add(timeout))
	tmp := make([]byte, max)
	n, _ := b.Conn.Read(tmp)
	_ = b.Conn.SetReadDeadline(time.Time{})
	if n > 0 {
		b.buf = append(b.buf, tmp[:n]...)
	}
	return b.buf
}

func (b *bufferedConn) prefetchRequest(max int, timeout time.Duration) []byte {
	_ = b.Conn.SetReadDeadline(time.Now().Add(timeout))
	defer b.Conn.SetReadDeadline(time.Time{})

	for len(b.buf) < max {
		if strings.Contains(string(b.buf), "\r\n\r\n") {
			break
		}
		tmp := make([]byte, 2048)
		n, err := b.Conn.Read(tmp)
		if n > 0 {
			b.buf = append(b.buf, tmp[:n]...)
		}
		if err != nil || n == 0 {
			break
		}
	}
	return b.buf
}

func (b *bufferedConn) forget(n int) {
	switch {
	case n <= 0:
		return
	case n >= len(b.buf):
		b.buf = nil
	default:
		b.buf = b.buf[n:]
	}
}

func (b *bufferedConn) Read(p []byte) (int, error) {
	if len(b.buf) > 0 {
		n := copy(p, b.buf)
		b.buf = b.buf[n:]
		return n, nil
	}
	return b.Conn.Read(p)
}

type Proxy struct {
	cfg      ProxyOptions
	resolver *resolver
	certs    *CertStore
	server   *net.TCPListener
	started  time.Time
	stopCh   chan struct{}
	wg       sync.WaitGroup

	domainMu sync.RWMutex
	table    *domainTable

	connSem chan struct{}

	statMu sync.Mutex
	stats  map[string]*ipStat

	probeMu sync.Mutex
	probeAt map[string]time.Time

	dynamicMu sync.Mutex
	dynamic   map[string][]string
	expandAt  map[string]time.Time
}

type ProxyOptions struct {
	Listen     string
	DomainFile string
	Resolver   *resolver
	Certs      *CertStore
	MaxConns   int
	BestFile   string
	StatsFile  string
}

type ipStat struct {
	rtt     time.Duration 
	rttAt   time.Time
	failAt  time.Time 
	failCnt int
	okCnt   int
}

func NewProxy(cfg ProxyOptions, res *resolver, table *domainTable, certs *CertStore) *Proxy {
	if cfg.MaxConns <= 0 {
		cfg.MaxConns = 128
	}
	return &Proxy{
		cfg:      cfg,
		resolver: res,
		certs:    certs,
		started:  time.Now(),
		stopCh:   make(chan struct{}),
		table:    table,
		connSem:  make(chan struct{}, cfg.MaxConns),
		stats:    make(map[string]*ipStat),
		probeAt:  make(map[string]time.Time),
		dynamic:  make(map[string][]string),
		expandAt: make(map[string]time.Time),
	}
}

func (p *Proxy) Start() error {
	addr, err := net.ResolveTCPAddr("tcp", p.cfg.Listen)
	if err != nil {
		return err
	}
	ln, err := net.ListenTCP("tcp", addr)
	if err != nil {
		return err
	}
	p.server = ln

	p.loadBest()
	logInfo("ghboost 启动: 监听 %s, fake IP 映射 %d 条, 并发上限 %d",
		p.cfg.Listen, p.domainCount(), p.cfg.MaxConns)

	p.spawn(p.acceptLoop)
	p.spawn(p.statsLoop)
	p.spawn(p.statusLoop)
	p.spawn(p.watchDomains)
	p.spawn(p.warmupLoop)
	return nil
}

func (p *Proxy) spawn(fn func()) {
	p.wg.Add(1)
	go func() {
		defer p.wg.Done()
		fn()
	}()
}

func (p *Proxy) Stop() {
	select {
	case <-p.stopCh:
	default:
		close(p.stopCh)
	}
	if p.server != nil {
		p.server.Close()
	}

	done := make(chan struct{})
	go func() {
		p.wg.Wait()
		close(done)
	}()
	select {
	case <-done:
		logInfo("ghboost 已停止")
	case <-time.After(3 * time.Second):
		logWarn("ghboost 停止超时: 还有活跃连接, 不再等待")
	}
}

func (p *Proxy) acceptLoop() {
	for {
		conn, err := p.server.Accept()
		if err != nil {
			select {
			case <-p.stopCh:
				return
			default:
				logError("accept 出错: %v", err)
				continue
			}
		}
		p.wg.Add(1)
		go func() {
			defer p.wg.Done()
			p.handleConn(conn.(*net.TCPConn))
		}()
	}
}

func (p *Proxy) handleConn(client *net.TCPConn) {
	defer client.Close()

	select {
	case p.connSem <- struct{}{}:
		defer func() { <-p.connSem }()
	default:
		bumpStat(false)
		logThrottled("conn-limit", "并发连接已达上限 %d, 拒绝新连接", cap(p.connSem))
		return
	}

	origAddr, err := getOriginalDst(client)
	if err != nil {
		bumpStat(false)
		logThrottled("orig-dst", "取原始目的地址失败, 来源 %s: %v", client.RemoteAddr(), err)
		return
	}

	domain, ok := p.lookupDomain(origAddr.IP.String())
	if !ok {
		bumpStat(false)
		logThrottled("unknown-ip", "未知 fake IP %s, 来源 %s, 关闭连接", origAddr.IP, client.RemoteAddr())
		return
	}

	port := origAddr.Port
	if port <= 0 {
		port = 443
	}
	portStr := strconv.Itoa(port)

	ips, err := p.resolver.Resolve(domain)
	if err != nil {
		bumpStat(false)
		logThrottled("resolve-"+domain, "%s 解析失败: %v", domain, err)
		return
	}
	ips = p.dropFakeIPs(p.withExtra(domain, ips))

	probed, anyOK := p.probeUntested(domain, ips, portStr)

	budget := dialBudget
	if probed && !anyOK {
		budget = dialFastBudget
		logThrottled("probe-dead-"+domain,
			"%s:%d 探测 %v 内没有候选建连成功, 重试预算缩短到 %v",
			domain, port, probeTimeout, budget)
	}

	ordered := p.order(domain, ips)

	bc := newBufferedConn(client)
	first, derr := bc.Peek(1)
	if derr != nil {
		bumpStat(false)
		return
	}
	if len(first) > 0 && first[0] == 0x16 {
		p.handleTLS(bc, domain, ordered, portStr, budget)
		return
	}

	p.handlePlain(bc, domain, ordered, portStr, budget)
}

func (p *Proxy) handlePlain(client net.Conn, domain string, ordered []string, portStr string, budget time.Duration) {
	deadline := time.Now().Add(budget)
	var dialErrs []string
	var replay []byte

	for round := 0; round < dialRounds; round++ {
		if round > 0 {
			select {
			case <-p.stopCh:
				return
			case <-time.After(dialPause):
			}
		}
		if time.Now().After(deadline) {
			break
		}
		for _, ip := range rotate(ordered, round) {
			if time.Now().After(deadline) {
				break
			}
			d := dialTimeout
			if rem := time.Until(deadline); rem < d {
				d = rem
			}
			if d <= 0 {
				break
			}

			start := time.Now()
			conn, derr := net.DialTimeout("tcp", net.JoinHostPort(ip, portStr), d)
			p.recordDial(domain, ip, time.Since(start), derr)
			if derr != nil {
				dialErrs = append(dialErrs, fmt.Sprintf("%s: %v", ip, derr))
				continue
			}

			res := relay(client, conn, relayIdle, replay)
			conn.Close()
			if res.recv > 0 {
				if res.aborted {
					p.recordDial(domain, ip, 0, errors.New("连接中途被断开"))
				}
				bumpStat(true)
				return
			}
			if res.sent > 0 {
				p.recordDial(domain, ip, 0, errors.New("首字节超时(服务器无响应)"))
				dialErrs = append(dialErrs, ip+": 首字节超时")
				if room := replayMax - len(replay); room > 0 {
					add := res.replay
					if len(add) > room {
						add = add[:room]
					}
					replay = append(replay, add...)
				}
				continue
			}

			p.recordDial(domain, ip, 0, errors.New("建立后立刻断开"))
			dialErrs = append(dialErrs, ip+": 建立后立刻断开")
		}
	}

	p.resolver.Forget(domain)
	bumpStat(false)
	logThrottled("dial-"+domain, "%s:%s 的候选 IP 全部不可用 -> %s",
		domain, portStr, strings.Join(dialErrs, " | "))
	go p.expandCandidates(domain, portStr, ordered)
}

func (p *Proxy) handleTLS(client net.Conn, domain string, ordered []string, portStr string, budget time.Duration) {
	if p.certs == nil {
		bumpStat(false)
		logThrottled("no-ca", "未配置 CA 证书，无法做 TLS MITM，回退明文中转")
		p.handlePlain(client, domain, ordered, portStr, budget)
		return
	}

	serverTLS, err := p.certs.ServerTLSConfig(domain)
	if err != nil {
		bumpStat(false)
		logThrottled("cert-"+domain, "生成 %s 叶子证书失败: %v", domain, err)
		return
	}

	clientTLS := tls.Server(client, serverTLS)
	if err := clientTLS.Handshake(); err != nil {
		bumpStat(false)
		logThrottled("client-hs-"+domain, "客户端 TLS 握手失败 %s: %v", client.RemoteAddr(), err)
		return
	}
	defer clientTLS.Close()

	sni := p.computeSNI(domain)
	skipVerify := p.ignoreCertMismatch(domain)

	cliBuf := newBufferedConn(clientTLS)
	reqHead := cliBuf.prefetchRequest(8<<10, 2*time.Second)
	if len(reqHead) == 0 || !strings.HasSuffix(string(reqHead), "\r\n\r\n") {
		reqHead = nil
	}
	reqPath := "/"
	if reqHead != nil {
		reqPath = requestPath(reqHead)
	}

	deadline := time.Now().Add(budget)
	var dialErrs []string

	for round := 0; round < dialRounds; round++ {
		if round > 0 {
			select {
			case <-p.stopCh:
				return
			case <-time.After(dialPause):
			}
		}
		if time.Now().After(deadline) {
			break
		}
		for _, ip := range rotate(ordered, round) {
			if time.Now().After(deadline) {
				break
			}
			d := dialTimeout
			if rem := time.Until(deadline); rem < d {
				d = rem
			}
			if d <= 0 {
				break
			}

			start := time.Now()
			raw, derr := net.DialTimeout("tcp", net.JoinHostPort(ip, portStr), d)
			if derr != nil {
				p.recordDial(domain, ip, time.Since(start), derr)
				dialErrs = append(dialErrs, fmt.Sprintf("%s: %v", ip, derr))
				continue
			}

			upstreamTLS := tls.Client(raw, &tls.Config{
				ServerName:         sni,
				InsecureSkipVerify: skipVerify,
				MinVersion:         tls.VersionTLS12,
			})
			if herr := upstreamTLS.Handshake(); herr != nil {
				p.recordDial(domain, ip, time.Since(start), herr)
				dialErrs = append(dialErrs, fmt.Sprintf("%s: tls %v", ip, herr))
				raw.Close()
				continue
			}

			if reqHead != nil {
				if _, werr := upstreamTLS.Write(reqHead); werr != nil {
					p.recordDial(domain, ip, 0, werr)
					dialErrs = append(dialErrs, fmt.Sprintf("%s: 发送请求失败: %v", ip, werr))
					upstreamTLS.Close()
					continue
				}
			}

			bufUp := newBufferedConn(upstreamTLS)
			var head []byte
			if reqHead != nil {
				head = bufUp.prefetch(2048, relayFirstByte)
			}
			if bad, why := badResponse(domain, reqPath, head); bad {
				p.recordDial(domain, ip, 0, errors.New(why))
				dialErrs = append(dialErrs, ip+": "+why)
				logThrottled("bad-upstream-"+domain, "%s:%s 上游 %s %s, 换下一个", domain, portStr, ip, why)
				upstreamTLS.Close()
				continue
			}

			p.recordDial(domain, ip, time.Since(start), nil)
			cliBuf.forget(len(reqHead))
			res := relay(cliBuf, bufUp, relayIdle, nil)
			upstreamTLS.Close()
			if res.recv > 0 || res.sent > 0 {
				if res.recv == 0 {
					p.recordDial(domain, ip, 0, errors.New("首字节超时(服务器无响应)"))
				} else if res.aborted {
					p.recordDial(domain, ip, 0, errors.New("连接中途被断开"))
				}
				bumpStat(true)
				return
			}
			dialErrs = append(dialErrs, ip+": 建立后立刻断开")
		}
	}

	p.resolver.Forget(domain)
	bumpStat(false)
	logThrottled("tls-dial-"+domain, "%s:%s TLS 候选 IP 全部不可用 -> %s",
		domain, portStr, strings.Join(dialErrs, " | "))
	go p.expandCandidates(domain, portStr, ordered)
}

func (p *Proxy) computeSNI(domain string) string {
	mode := p.domainSNIMode(domain)
	switch mode {
	case SNIModeNone:
		return ""
	case SNIModeRandom:
		return fmt.Sprintf("%d.%d", time.Now().UnixNano(), rand.Intn(100000))
	case SNIModeDomain:
		return domain
	default:
		return mode
	}
}

func (p *Proxy) domainSNIMode(domain string) string {
	p.domainMu.RLock()
	mode := p.table.sniModeOf(domain)
	p.domainMu.RUnlock()
	return mode
}

func (p *Proxy) ignoreCertMismatch(domain string) bool {
	p.domainMu.RLock()
	skip := p.table.ignoreCertMismatchOf(domain)
	p.domainMu.RUnlock()
	return skip
}

func (p *Proxy) expandCandidates(domain, port string, tried []string) {
	p.dynamicMu.Lock()
	if at, ok := p.expandAt[domain]; ok && time.Since(at) < expandCooldown {
		p.dynamicMu.Unlock()
		return
	}
	p.expandAt[domain] = time.Now()
	p.dynamicMu.Unlock()

	seen := make(map[string]bool, len(tried)+len(ghPrefixes)*expandPerPrefix)
	for _, ip := range tried {
		seen[ip] = true
	}

	rnd := rand.New(rand.NewSource(time.Now().UnixNano()))
	var cands []string
	for _, prefix := range ghPrefixes {
		for k := 0; k < expandPerPrefix; k++ {
			ip := fmt.Sprintf("%s%d", prefix, rnd.Intn(254)+1)
			if seen[ip] {
				continue
			}
			seen[ip] = true
			cands = append(cands, ip)
		}
	}
	if len(cands) == 0 {
		return
	}

	sem := make(chan struct{}, warmupConcurrency)
	var wg sync.WaitGroup
	var mu sync.Mutex
	found := make([]string, 0, 4)

	for _, ip := range cands {
		select {
		case <-p.stopCh:
			return
		default:
		}
		wg.Add(1)
		sem <- struct{}{}
		go func(ip string) {
			defer wg.Done()
			defer func() { <-sem }()
			sni := p.computeSNI(domain)
			skipVerify := p.ignoreCertMismatch(domain)
			elapsed, derr := tlsProbe(ip, domain, sni, skipVerify, port, expandTimeout, true)
			if derr != nil {
				return
			}
			p.recordDial(domain, ip, elapsed, nil)
			mu.Lock()
			found = append(found, ip)
			mu.Unlock()
		}(ip)
	}
	wg.Wait()

	if len(found) == 0 {
		logWarn("%s: 扫描 %d 个 IP, 全部不可用", domain, len(cands))
		return
	}

	p.dynamicMu.Lock()
	cur := append([]string(nil), p.dynamic[domain]...)
	for _, ip := range found {
		dup := false
		for _, old := range cur {
			if old == ip {
				dup = true
				break
			}
		}
		if !dup {
			cur = append(cur, ip)
		}
	}
	if len(cur) > dynamicExtraMax {
		cur = cur[len(cur)-dynamicExtraMax:]
	}
	p.dynamic[domain] = cur
	p.dynamicMu.Unlock()

	logInfo("%s: 扫描 %d 个 IP, 新增 %d 个可用", domain, len(cands), len(found))
}

const replayMax = 64 << 10

type relayResult struct {
	sent    int64
	recv    int64
	replay  []byte
	aborted bool
}

type replayReader struct {
	r        io.Reader
	answered *atomic.Bool 
	mu       sync.Mutex
	buf      []byte
}

func (r *replayReader) Read(p []byte) (int, error) {
	n, err := r.r.Read(p)
	if n > 0 && !r.answered.Load() {
		r.mu.Lock()
		if room := replayMax - len(r.buf); room > 0 {
			m := n
			if m > room {
				m = room
			}
			r.buf = append(r.buf, p[:m]...)
		}
		r.mu.Unlock()
	}
	return n, err
}

func (r *replayReader) snapshot() []byte {
	r.mu.Lock()
	defer r.mu.Unlock()
	if len(r.buf) == 0 {
		return nil
	}
	out := make([]byte, len(r.buf))
	copy(out, r.buf)
	return out
}

type idleReader struct {
	conn      net.Conn
	idle      time.Duration
	firstByte time.Duration
	peerSent  *atomic.Int64
	got       bool
	lastErr   error
	deadline  time.Time
}

const deadlineSlack = 5 * time.Second

func (r *idleReader) Read(b []byte) (int, error) {
	d := r.idle
	if r.firstByte > 0 && r.peerSent != nil && !r.got && r.peerSent.Load() > 0 {
		d = r.firstByte
	}
	now := time.Now()
	if r.deadline.IsZero() || d <= deadlineSlack || r.deadline.Sub(now) < d-deadlineSlack {
		r.deadline = now.Add(d)
		_ = r.conn.SetReadDeadline(r.deadline)
	}
	n, err := r.conn.Read(b)
	if n > 0 {
		r.got = true
	}
	if err != nil && err != io.EOF {
		r.lastErr = err
	}
	return n, err
}

func relay(client, upstream net.Conn, idle time.Duration, replay []byte) relayResult {
	const (
		dirUp   = 1 
		dirDown = 2 
	)

	closeWrite := func(c net.Conn) {
		if hc, ok := c.(interface{ CloseWrite() error }); ok {
			_ = hc.CloseWrite()
		}
	}

	var sent, recv atomic.Int64
	var answered atomic.Bool
	done := make(chan int, 2)
	up := &replayReader{r: &idleReader{conn: client, idle: idle}, answered: &answered}
	downReader := &idleReader{conn: upstream, idle: idle, firstByte: relayFirstByte, peerSent: &sent}

	if len(replay) > 0 {
		if n, err := upstream.Write(replay); err == nil {
			sent.Add(int64(n))
		}
	}

	go func() {
		n, _ := io.Copy(upstream, up)
		sent.Add(n)
		closeWrite(upstream)
		done <- dirUp
	}()
	go func() {
		n, _ := io.Copy(client, downReader)
		recv.Add(n)
		if n > 0 {
			answered.Store(true)
		}
		if n > 0 {
			closeWrite(client)
		}
		done <- dirDown
	}()

	first := <-done
	if sent.Load() == 0 && recv.Load() == 0 {
		if first == dirDown {
			_ = client.SetReadDeadline(time.Now())
		} else {
			_ = upstream.SetReadDeadline(time.Now())
		}
		<-done
		_ = client.SetReadDeadline(time.Time{})
	} else if recv.Load() == 0 {
		_ = client.SetReadDeadline(time.Now())
		<-done
		_ = client.SetReadDeadline(time.Time{})
	} else {
		<-done
	}

	res := relayResult{sent: sent.Load(), recv: recv.Load()}
	if res.recv == 0 {
		res.replay = up.snapshot()
	}
	if first == dirDown && downReader.lastErr != nil {
		res.aborted = true
	}
	return res
}

func (p *Proxy) probeUntested(domain string, ips []string, port string) (probed bool, anyOK bool) {
	var todo []string
	for _, ip := range ips {
		if st := p.statOf(domain, ip); st == nil || st.rttAt.IsZero() {
			todo = append(todo, ip)
		}
	}
	if len(todo) == 0 || !p.allowProbe(domain) {
		return false, false
	}

	sni := p.computeSNI(domain)
	skipVerify := p.ignoreCertMismatch(domain)

	hit := make(chan struct{}, len(todo))
	for _, ip := range todo {
		go func(ip string) {
			start := time.Now()
			c, err := net.DialTimeout("tcp", net.JoinHostPort(ip, port), probeTimeout)
			if err != nil {
				return
			}
			defer c.Close()
			hit <- struct{}{}

			if port == "443" {
				if herr := checkPeer(c, domain, sni, skipVerify, probeTimeout*2, true); herr != nil {
					p.recordDial(domain, ip, 0, fmt.Errorf("TLS/HTTP 校验失败: %v", herr))
					return
				}
			}
			p.recordDial(domain, ip, time.Since(start), nil)
		}(ip)
	}

	select {
	case <-hit:
		return true, true
	case <-time.After(probeTimeout):
		return true, false
	}
}

func (p *Proxy) allowProbe(domain string) bool {
	p.probeMu.Lock()
	defer p.probeMu.Unlock()

	now := time.Now()
	if last, ok := p.probeAt[domain]; ok && now.Sub(last) < probeCooldown {
		return false
	}
	p.probeAt[domain] = now

	if len(p.probeAt) > 512 {
		for d, t := range p.probeAt {
			if now.Sub(t) > probeCooldown {
				delete(p.probeAt, d)
			}
		}
	}
	return true
}

func (p *Proxy) order(domain string, ips []string) []string {
	type item struct {
		ip    string
		rtt   time.Duration
		known bool
		bad   bool
	}

	now := time.Now()
	p.statMu.Lock()
	items := make([]item, 0, len(ips))
	for _, ip := range ips {
		it := item{ip: ip}
		if st := p.stats[domain+"|"+ip]; st != nil {
			if st.failCnt > 0 && st.failAt.After(st.rttAt) && now.Sub(st.failAt) < failPenalty {
				it.bad = true
			}
			if st.rtt > 0 {
				it.rtt = st.rtt
				it.known = true
			}
		}
		items = append(items, it)
	}
	p.statMu.Unlock()

	sort.SliceStable(items, func(i, j int) bool {
		a, b := items[i], items[j]
		if a.bad != b.bad {
			return !a.bad
		}
		if a.known != b.known {
			return a.known
		}
		if a.known && b.known {
			return a.rtt < b.rtt
		}
		return false
	})

	out := make([]string, len(items))
	for i, it := range items {
		out[i] = it.ip
	}
	return out
}

func (p *Proxy) recordDial(domain, ip string, d time.Duration, err error) {
	key := domain + "|" + ip
	p.statMu.Lock()
	st := p.stats[key]
	if st == nil {
		st = &ipStat{}
		p.stats[key] = st
	}
	if err == nil {
		st.rtt = d
		st.rttAt = time.Now()
		st.failCnt = 0
		st.okCnt++
	} else {
		st.failAt = time.Now()
		st.failCnt++
	}
	p.statMu.Unlock()
}

func rotate(ips []string, n int) []string {
	if len(ips) < 2 {
		return ips
	}
	n = n % len(ips)
	if n == 0 {
		return ips
	}
	out := make([]string, 0, len(ips))
	out = append(out, ips[n:]...)
	out = append(out, ips[:n]...)
	return out
}

func (p *Proxy) lookupDomain(ip string) (string, bool) {
	p.domainMu.RLock()
	d, ok := p.table.domainOf(ip)
	p.domainMu.RUnlock()
	return d, ok
}

func (p *Proxy) domainCount() int {
	p.domainMu.RLock()
	n := p.table.len()
	p.domainMu.RUnlock()
	return n
}

func (p *Proxy) domainList() []string {
	p.domainMu.RLock()
	names := p.table.names()
	p.domainMu.RUnlock()
	return names
}

func (p *Proxy) domainPairs() [][2]string {
	p.domainMu.RLock()
	pairs := p.table.pairs()
	p.domainMu.RUnlock()
	return pairs
}

func (p *Proxy) withExtra(domain string, ips []string) []string {
	p.domainMu.RLock()
	extra := p.table.extrasOf(domain)
	p.domainMu.RUnlock()

	p.dynamicMu.Lock()
	dyn := append([]string(nil), p.dynamic[domain]...)
	p.dynamicMu.Unlock()

	if len(extra) == 0 && len(dyn) == 0 {
		return ips
	}

	seen := make(map[string]bool, len(extra)+len(dyn)+len(ips))
	out := make([]string, 0, len(extra)+len(dyn)+len(ips))
	for _, list := range [][]string{extra, dyn, ips} {
		for _, ip := range list {
			if !seen[ip] {
				seen[ip] = true
				out = append(out, ip)
			}
		}
	}
	return out
}

func (p *Proxy) dropFakeIPs(ips []string) []string {
	if len(ips) == 0 {
		return ips
	}
	out := make([]string, 0, len(ips))
	dropped, bogus := 0, 0
	for _, ip := range ips {
		if _, isFake := p.lookupDomain(ip); isFake {
			dropped++
			continue
		}
		if isBogusIP(ip) {
			bogus++
			continue
		}
		out = append(out, ip)
	}
	if dropped > 0 {
		logThrottled("fake-upstream",
			"DNS 上游返回 %d 个 fake IP, 已丢弃: 上游是本机 dnsmasq", dropped)
	}
	if bogus > 0 {
		logThrottled("bogus-upstream",
			"DNS 上游返回 %d 个污染 IP, 已丢弃", bogus)
	}
	return out
}

var bogusIPs = map[string]bool{
	"0.0.0.0":         true,
	"159.106.121.75":  true,
	"37.61.54.158":    true,
	"46.82.174.68":    true,
	"78.16.49.15":     true,
	"203.98.7.65":     true,
	"8.7.198.45":      true,
	"93.46.8.89":      true,
	"243.185.187.39":  true,
	"4.36.66.178":     true,
	"2001::1":         true,
	"2001:db8::1":     true,
}

func isBogusIP(ip string) bool {
	if ip == "" || ip == "0.0.0.0" || ip == "::" {
		return true
	}
	return bogusIPs[ip]
}

func anyIPv4(ips []string) bool {
	for _, s := range ips {
		if ip := net.ParseIP(s); ip != nil && ip.To4() != nil {
			return true
		}
	}
	return false
}

func lessIP(a, b string) bool {
	ia, ib := net.ParseIP(a), net.ParseIP(b)
	if ia == nil || ib == nil {
		return a < b
	}
	return bytesCompare(ia.To16(), ib.To16()) < 0
}

func bytesCompare(a, b []byte) int {
	for i := 0; i < len(a) && i < len(b); i++ {
		if a[i] != b[i] {
			if a[i] < b[i] {
				return -1
			}
			return 1
		}
	}
	return 0
}

func sortFakePairs(pairs [][2]string) {
	sort.Slice(pairs, func(i, j int) bool { return lessIP(pairs[i][0], pairs[j][0]) })
}

func (p *Proxy) reloadDomains() error {
	table, err := LoadDomains(p.cfg.DomainFile)
	if err != nil {
		return err
	}
	if table.len() == 0 {
		return errors.New("域名映射为空")
	}

	p.domainMu.Lock()
	old := p.table.len()
	p.table = table
	p.domainMu.Unlock()

	logInfo("域名映射已重载: %d -> %d 条", old, table.len())
	return nil
}

func (p *Proxy) watchDomains() {
	var lastMod time.Time
	if fi, err := os.Stat(p.cfg.DomainFile); err == nil {
		lastMod = fi.ModTime()
	}

	t := time.NewTicker(10 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-p.stopCh:
			return
		case <-t.C:
			fi, err := os.Stat(p.cfg.DomainFile)
			if err != nil || !fi.ModTime().After(lastMod) {
				continue
			}
			lastMod = fi.ModTime()
			if err := p.reloadDomains(); err != nil {
				logError("域名映射重载失败: %v", err)
			}
		}
	}
}

func requestPath(head []byte) string {
	s := string(head)
	line := s
	if i := strings.IndexByte(s, '\r'); i > 0 {
		line = s[:i]
	}
	parts := strings.SplitN(line, " ", 3)
	if len(parts) < 2 {
		return "/"
	}
	p := parts[1]
	if i := strings.IndexByte(p, '?'); i >= 0 {
		p = p[:i]
	}
	return p
}

func badResponse(domain, reqPath string, head []byte) (bool, string) {
	if len(head) == 0 {
		return false, ""
	}

	status := 0
	lines := strings.Split(string(head), "\r\n")
	if f := strings.Fields(lines[0]); len(f) >= 2 {
		if n, err := strconv.Atoi(f[1]); err == nil {
			status = n
		}
	}

	lower := strings.ToLower(string(head))
	if strings.Contains(lower, "microsoft-iis") || strings.Contains(lower, "x-powered-by: asp.net") ||
		strings.Contains(lower, "web site not found") {
		return true, "命中 Azure 默认站点"
	}

	if status < 300 || status >= 400 {
		return false, ""
	}

	for _, l := range lines[1:] {
		if len(l) < 9 || !strings.EqualFold(l[:9], "location:") {
			continue
		}
		u, err := url.Parse(strings.TrimSpace(l[9:]))
		if err != nil || u.Host == "" {
			return false, ""
		}
		host := strings.ToLower(u.Hostname())
		if host == "github.com" && !strings.EqualFold(domain, "github.com") &&
			reqPath != "/" && u.Path == reqPath {
			return true, "被跳转到 " + host
		}
		return false, ""
	}
	return false, ""
}

func checkPeer(raw net.Conn, domain, sni string, skipVerify bool, timeout time.Duration, httpCheck bool) error {
	_ = raw.SetDeadline(time.Now().Add(timeout))

	tc := tls.Client(raw, &tls.Config{
		ServerName:         sni,
		InsecureSkipVerify: skipVerify,
		MinVersion:         tls.VersionTLS12,
	})
	if err := tc.Handshake(); err != nil {
		return err
	}

	if !httpCheck {
		return nil
	}

	req := "HEAD / HTTP/1.1\r\nHost: " + domain +
		"\r\nUser-Agent: ghboost-probe\r\nConnection: close\r\n\r\n"
	if _, err := io.WriteString(tc, req); err != nil {
		return err
	}
	buf := make([]byte, 2048)
	n, err := tc.Read(buf)
	if n == 0 {
		if err != nil {
			return err
		}
		return errors.New("空响应")
	}
	if n < 5 || string(buf[:5]) != "HTTP/" {
		return fmt.Errorf("非 HTTP 响应: %q", buf[:n])
	}
	if bad, why := badResponse(domain, "/", buf[:n]); bad {
		return fmt.Errorf("响应不属于本站点: %s", why)
	}
	return nil
}

func tlsProbe(ip, domain, sni string, skipVerify bool, port string, timeout time.Duration, httpCheck bool) (time.Duration, error) {
	start := time.Now()
	raw, err := net.DialTimeout("tcp", net.JoinHostPort(ip, port), timeout)
	if err != nil {
		return 0, err
	}
	defer raw.Close()

	if port != "443" {
		return time.Since(start), nil
	}

	if err := checkPeer(raw, domain, sni, skipVerify, timeout, httpCheck); err != nil {
		return 0, err
	}
	return time.Since(start), nil
}

func (p *Proxy) warmupLoop() {
	timer := time.NewTimer(5 * time.Second)
	defer timer.Stop()
	select {
	case <-p.stopCh:
		return
	case <-timer.C:
		p.warmupOnce()
	}
}

func (p *Proxy) warmupOnce() {
	doms := p.domainList()
	if len(doms) == 0 {
		return
	}
	start := time.Now()

	var probed int64
	sem := make(chan struct{}, warmupConcurrency)
	var wg sync.WaitGroup

	for _, d := range doms {
		select {
		case <-p.stopCh:
			return
		default:
		}

		ips, err := p.resolver.Resolve(d)
		if err != nil {
			logThrottled("warm-"+d, "预热解析 %s 失败: %v", d, err)
			continue
		}
		ips = p.dropFakeIPs(p.withExtra(d, ips))
		if len(ips) > 0 && !anyIPv4(ips) {
			logThrottled("warm-v6-"+d,
				"预热: %s 只解析到 IPv6 %s", d, ips[0])
		}
		for i, ip := range ips {
			if i >= warmupProbeCount {
				break
			}
			if st := p.statOf(d, ip); st != nil && st.failCnt > 0 {
				if time.Since(st.failAt) < warmupSkipFail {
					continue
				}
			}
			wg.Add(1)
			sem <- struct{}{}
			go func(d, ip string) {
				defer wg.Done()
				defer func() { <-sem }()
				sni := p.computeSNI(d)
				skipVerify := p.ignoreCertMismatch(d)
				elapsed, derr := tlsProbe(ip, d, sni, skipVerify, warmupPort, dialTimeout, true)
				p.recordDial(d, ip, elapsed, derr)
				atomic.AddInt64(&probed, 1)
			}(d, ip)
		}
	}
	wg.Wait()

	p.saveBest()
	logInfo("预热完成: %d 个域名, 测速 %d 个候选 IP, 耗时 %v",
		len(doms), probed, time.Since(start).Round(time.Millisecond))
}

func (p *Proxy) statOf(domain, ip string) *ipStat {
	p.statMu.Lock()
	st := p.stats[domain+"|"+ip]
	var cp *ipStat
	if st != nil {
		dup := *st
		cp = &dup
	}
	p.statMu.Unlock()
	return cp
}

type bestEntry struct {
	RTTMs  int64     `json:"rtt_ms"`
	FailAt time.Time `json:"fail_at,omitempty"`
	At     time.Time `json:"at"`
}

func (p *Proxy) saveBest() {
	if p.cfg.BestFile == "" {
		return
	}
	out := make(map[string]map[string]bestEntry)
	p.statMu.Lock()
	for k, st := range p.stats {
		idx := strings.IndexByte(k, '|')
		if idx <= 0 {
			continue
		}
		d, ip := k[:idx], k[idx+1:]
		m := out[d]
		if m == nil {
			m = make(map[string]bestEntry)
			out[d] = m
		}
		m[ip] = bestEntry{RTTMs: st.rtt.Milliseconds(), FailAt: st.failAt, At: st.rttAt}
	}
	p.statMu.Unlock()

	if err := writeJSONAtomic(p.cfg.BestFile, out); err != nil {
		logWarn("写测速结果失败: %v", err)
	}
}

func (p *Proxy) loadBest() {
	if p.cfg.BestFile == "" {
		return
	}
	data, err := os.ReadFile(p.cfg.BestFile)
	if err != nil {
		return
	}
	var in map[string]map[string]bestEntry
	if err := unmarshalJSON(data, &in); err != nil {
		logWarn("读测速结果失败, 忽略: %v", err)
		return
	}

	now := time.Now()
	loaded := 0
	p.statMu.Lock()
	for d, ips := range in {
		for ip, e := range ips {
			if now.Sub(e.At) > 6*time.Hour && now.Sub(e.FailAt) > 6*time.Hour {
				continue
			}
			p.stats[d+"|"+ip] = &ipStat{
				rtt:     time.Duration(e.RTTMs) * time.Millisecond,
				rttAt:   e.At,
				failAt:  e.FailAt,
				failCnt: boolToInt(!e.FailAt.IsZero()),
			}
			loaded++
		}
	}
	p.statMu.Unlock()
	if loaded > 0 {
		logInfo("已载入 %d 条历史测速结果: %s", loaded, p.cfg.BestFile)
	}
}

func boolToInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

const (
	statBucketDur = 5 * time.Second
	statBuckets   = 12 
)

type statWindow struct {
	mu     sync.Mutex
	ok     [statBuckets]int64
	fail   [statBuckets]int64
	slot   int
	slotAt time.Time
	total  int64
}

func (w *statWindow) bump(ok bool, now time.Time) {
	w.mu.Lock()
	w.advance(now)
	if ok {
		w.ok[w.slot]++
	} else {
		w.fail[w.slot]++
	}
	w.total++
	w.mu.Unlock()
}

func (w *statWindow) advance(now time.Time) {
	if w.slotAt.IsZero() {
		w.slotAt = now
		return
	}
	if now.Sub(w.slotAt) >= statBuckets*statBucketDur {
		for i := 0; i < statBuckets; i++ {
			w.ok[i], w.fail[i] = 0, 0
		}
		w.slot = 0
		w.slotAt = now
		return
	}
	for now.Sub(w.slotAt) >= statBucketDur {
		w.slot = (w.slot + 1) % statBuckets
		w.ok[w.slot], w.fail[w.slot] = 0, 0
		w.slotAt = w.slotAt.Add(statBucketDur)
	}
}

func (w *statWindow) recent(now time.Time) (ok, fail, total int64) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.advance(now)

	for i := 0; i < statBuckets; i++ {
		ok += w.ok[i]
		fail += w.fail[i]
	}
	return ok, fail, w.total
}

var connStats statWindow

func bumpStat(ok bool) {
	connStats.bump(ok, time.Now())
}

func (p *Proxy) statsLoop() {
	t := time.NewTicker(60 * time.Second)
	defer t.Stop()
	tick := 0
	for {
		select {
		case <-p.stopCh:
			return
		case <-t.C:
			tick++
			ok, fail, total := connStats.recent(time.Now())
			if fail > 0 || tick%30 == 0 {
				logInfo("近 60 秒: 成功 %d 条, 失败 %d 条, 累计 %d 条", ok, fail, total)
			}

			p.statMu.Lock()
			for k, st := range p.stats {
				last := st.rttAt
				if st.failAt.After(last) {
					last = st.failAt
				}
				keep := 30 * time.Minute
				if st.rtt > 0 {
					keep = 6 * time.Hour
				}
				if time.Since(last) > keep {
					delete(p.stats, k)
				}
			}
			p.statMu.Unlock()
		}
	}
}

var (
	logThrottleMu   sync.Mutex
	logThrottleLast = map[string]time.Time{}
)

func logThrottled(key, format string, args ...interface{}) {
	logThrottleMu.Lock()
	last, ok := logThrottleLast[key]
	now := time.Now()
	if ok && now.Sub(last) < 10*time.Second {
		logThrottleMu.Unlock()
		return
	}
	if len(logThrottleLast) > 4096 {
		for k, t := range logThrottleLast {
			if now.Sub(t) > 10*time.Minute {
				delete(logThrottleLast, k)
			}
		}
	}
	logThrottleLast[key] = now
	logThrottleMu.Unlock()

	logWarn(format, args...)
}
