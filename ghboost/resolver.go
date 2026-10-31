package main

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

const (
	resolveMinTTL = 30 * time.Second
	resolveMaxTTL = 10 * time.Minute
	queryTimeout = 3 * time.Second
	resultGrace = 300 * time.Millisecond
	upstreamFailLimit = 3
	upstreamCooldown  = 30 * time.Second
	maxCNAMEHops = 2
)

const (
	dnsTypeA     uint16 = 1
	dnsTypeCNAME uint16 = 5
	dnsTypeAAAA  uint16 = 28
)

type upstream struct {
	raw  string 
	doh  string 
	addr string 

	ecs     net.IP
	ecsName string

	failCnt int
	downTo  time.Time
}

func sanitizeUpstream(s string) string {
	var b strings.Builder
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
			b.WriteRune(r)
		case strings.ContainsRune(":/._-[]%@?=&", r):
			b.WriteRune(r)
		}
	}
	return b.String()
}

func parseUpstreams(spec string) ([]upstream, error) {
	var out []upstream
	for _, item := range strings.FieldsFunc(spec, func(r rune) bool {
		return r == ',' || r == '\n' || r == '\r'
	}) {
		item = sanitizeUpstream(strings.TrimSpace(item))
		if item == "" {
			continue
		}
		if strings.HasPrefix(item, "http://") || strings.HasPrefix(item, "https://") {
			out = append(out, upstream{raw: item, doh: item})
			continue
		}
		addr := item
		if !strings.Contains(addr, ":") {
			addr += ":53"
		}
		if _, _, err := net.SplitHostPort(addr); err != nil {
			return nil, fmt.Errorf("无法识别的 DNS 上游 %q: %w", item, err)
		}
		out = append(out, upstream{raw: item, addr: addr})
	}
	if len(out) == 0 {
		return nil, errors.New("DNS 上游列表为空")
	}

	for i := range out {
		if i == 0 {
			continue
		}
		region := ecsRegions[(i-1)%len(ecsRegions)]
		out[i].ecs = region.ip
		out[i].ecsName = region.name
	}
	return out, nil
}

type dnsAnswer struct {
	ip  string
	ttl uint32
	v6  bool
}

type cacheEntry struct {
	ips    []string
	expire time.Time
}

type flight struct {
	done chan struct{}
	ips  []string
	err  error
}

type resolver struct {
	upstreams []upstream
	client    *http.Client
	ipv6 bool

	mu      sync.Mutex
	cache   map[string]cacheEntry
	flights map[string]*flight
}

func newResolver(spec string) (*resolver, error) {
	ups, err := parseUpstreams(spec)
	if err != nil {
		return nil, err
	}
	return &resolver{
		upstreams: ups,
		client: &http.Client{
			Timeout: 8 * time.Second,
			Transport: &http.Transport{
				ForceAttemptHTTP2:   true,
				TLSHandshakeTimeout: 6 * time.Second,
				MaxIdleConns:        16,
				MaxIdleConnsPerHost: 8,
				IdleConnTimeout:     90 * time.Second,
			},
		},
		ipv6:    hasGlobalIPv6(),
		cache:   make(map[string]cacheEntry),
		flights: make(map[string]*flight),
	}, nil
}

func hasGlobalIPv6() bool {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return false
	}
	for _, a := range addrs {
		ipnet, ok := a.(*net.IPNet)
		if !ok || ipnet.IP.To4() != nil {
			continue
		}
		ip := ipnet.IP
		if ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() {
			continue
		}
		return true
	}
	return false
}

func (r *resolver) Resolve(domain string) ([]string, error) {
	r.mu.Lock()
	if e, ok := r.cache[domain]; ok && time.Now().Before(e.expire) {
		ips := e.ips
		r.mu.Unlock()
		return ips, nil
	}
	if f, ok := r.flights[domain]; ok {
		r.mu.Unlock()
		<-f.done
		return f.ips, f.err
	}
	f := &flight{done: make(chan struct{})}
	r.flights[domain] = f
	r.mu.Unlock()

	ips, ttlSec, err := r.lookup(domain, 0)

	r.mu.Lock()
	if err == nil && len(ips) > 0 {
		r.cache[domain] = cacheEntry{ips: ips, expire: time.Now().Add(ttlOf(ttlSec))}
	}
	delete(r.flights, domain)
	r.mu.Unlock()

	f.ips, f.err = ips, err
	close(f.done)
	return ips, err
}

func ttlOf(ttlSec uint32) time.Duration {
	d := time.Duration(ttlSec) * time.Second
	if d < resolveMinTTL {
		return resolveMinTTL
	}
	if d > resolveMaxTTL {
		return resolveMaxTTL
	}
	return d
}

func (r *resolver) lookup(domain string, depth int) ([]string, uint32, error) {
	if _, err := buildDNSQuery(domain, dnsTypeA, nil); err != nil {
		return nil, 0, err
	}

	ups := r.pickUpstreams()
	ctx, cancel := context.WithTimeout(context.Background(), queryTimeout)
	defer cancel()

	type result struct {
		up      *upstream
		answers []dnsAnswer
		cnames  []string
		err     error
	}

	slots := len(ups)
	if r.ipv6 {
		slots *= 2
	}
	ch := make(chan result, slots)
	for _, up := range ups {
		go func(up *upstream) {
			q4, err := buildDNSQuery(domain, dnsTypeA, up.ecs)
			if err != nil {
				ch <- result{up: up, err: err}
				if r.ipv6 {
					ch <- result{up: up, err: err}
				}
				return
			}
			answers, cnames, e := r.queryOne(ctx, up, q4)
			ch <- result{up: up, answers: answers, cnames: cnames, err: e}

			if r.ipv6 {
				q6, err := buildDNSQuery(domain, dnsTypeAAAA, up.ecs)
				if err != nil {
					ch <- result{up: up, err: err}
					return
				}
				answers, cnames, e = r.queryOne(ctx, up, q6)
				ch <- result{up: up, answers: answers, cnames: cnames, err: e}
			}
		}(up)
	}

	var (
		v4, v6   []string
		cnames   []string
		seen     = make(map[string]bool)
		minTTL   uint32
		firstErr error
		graceCh  <-chan time.Time
		pending  = slots
	)

	for pending > 0 {
		select {
		case res := <-ch:
			pending--
			if res.err != nil {
				r.markFail(res.up, res.err)
				if firstErr == nil {
					firstErr = res.err
				}
				continue
			}
			r.markOK(res.up)
			for _, a := range res.answers {
				if seen[a.ip] {
					continue
				}
				seen[a.ip] = true
				if a.v6 {
					v6 = append(v6, a.ip)
				} else {
					v4 = append(v4, a.ip)
				}
				if minTTL == 0 || a.ttl < minTTL {
					minTTL = a.ttl
				}
			}
			cnames = append(cnames, res.cnames...)
			if graceCh == nil && len(v4)+len(v6) > 0 {
				graceCh = time.After(resultGrace)
			}
		case <-graceCh:
			pending = 0
		case <-ctx.Done():
			pending = 0
		}
	}

	ips := make([]string, 0, len(v4)+len(v6))
	ips = append(ips, v4...)
	ips = append(ips, v6...)

	if len(ips) == 0 && len(cnames) > 0 && depth < maxCNAMEHops {
		for _, cn := range dedupStrings(cnames) {
			if cn == "" || strings.EqualFold(cn, domain) {
				continue
			}
			tips, ttl, terr := r.lookup(cn, depth+1)
			if terr != nil {
				continue
			}
			ips = append(ips, tips...)
			if minTTL == 0 || ttl < minTTL {
				minTTL = ttl
			}
			logThrottled("cname-"+domain, "%s 只有 CNAME, 按 %s 的解析结果使用", domain, cn)
		}
	}

	if len(ips) == 0 {
		if firstErr != nil {
			return nil, 0, firstErr
		}
		return nil, 0, fmt.Errorf("%s: 上游没有返回 A/AAAA 记录", domain)
	}
	return ips, minTTL, nil
}

func (r *resolver) pickUpstreams() []*upstream {
	r.mu.Lock()
	defer r.mu.Unlock()

	now := time.Now()
	healthy := make([]*upstream, 0, len(r.upstreams))
	cooled := make([]*upstream, 0, len(r.upstreams))
	for i := range r.upstreams {
		up := &r.upstreams[i]
		if up.failCnt >= upstreamFailLimit {
			if now.Before(up.downTo) {
				cooled = append(cooled, up)
				continue
			}
			up.failCnt = 0
		}
		healthy = append(healthy, up)
	}
	if len(healthy) == 0 {
		return cooled
	}
	return healthy
}

func (r *resolver) markOK(up *upstream) {
	r.mu.Lock()
	wasDown := !up.downTo.IsZero() || up.failCnt >= upstreamFailLimit
	up.failCnt = 0
	up.downTo = time.Time{}
	r.mu.Unlock()

	if wasDown {
		logInfo("DNS 上游已恢复: %s", up.raw)
	}
}

func (r *resolver) markFail(up *upstream, cause error) {
	r.mu.Lock()
	up.failCnt++
	tripped := false
	if up.failCnt >= upstreamFailLimit {
		if up.downTo.IsZero() || time.Now().After(up.downTo) {
			tripped = true
		}
		up.downTo = time.Now().Add(upstreamCooldown)
	}
	cnt := up.failCnt
	r.mu.Unlock()

	if tripped {
		why := ""
		if cause != nil {
			why = ": " + cause.Error()
		}
		logWarn("DNS 上游不可用: %s, 连续失败 %d 次%s, 暂停 %v",
			up.raw, cnt, why, upstreamCooldown)
	}
}

func (r *resolver) Forget(domain string) {
	r.mu.Lock()
	delete(r.cache, domain)
	r.mu.Unlock()
}

type UpstreamStatus struct {
	Raw string `json:"raw"`
	InUse bool `json:"in_use"`
	DownSec int `json:"down_sec"`
	FailCnt int `json:"fail_cnt"`
}

func (r *resolver) Status() []UpstreamStatus {
	r.mu.Lock()
	defer r.mu.Unlock()

	now := time.Now()
	out := make([]UpstreamStatus, 0, len(r.upstreams))
	for _, up := range r.upstreams {
		down := 0
		if up.failCnt >= upstreamFailLimit && now.Before(up.downTo) {
			down = int(up.downTo.Sub(now).Seconds()) + 1
		}
		out = append(out, UpstreamStatus{
			Raw:     up.raw,
			InUse:   down == 0,
			DownSec: down,
			FailCnt: up.failCnt,
		})
	}
	return out
}

type CachedDomain struct {
	IPs    []string  `json:"ips"`
	Expire time.Time `json:"expire"`
}

func (r *resolver) CachedDomains() map[string]CachedDomain {
	r.mu.Lock()
	defer r.mu.Unlock()

	out := make(map[string]CachedDomain, len(r.cache))
	for d, e := range r.cache {
		ips := make([]string, len(e.ips))
		copy(ips, e.ips)
		out[d] = CachedDomain{IPs: ips, Expire: e.expire}
	}
	return out
}

func (r *resolver) queryOne(ctx context.Context, up *upstream, q []byte) ([]dnsAnswer, []string, error) {
	var msg []byte
	var err error

	switch {
	case up.doh != "":
		msg, err = r.queryDoH(ctx, up.doh, q)
	case up.addr != "":
		msg, err = queryDNS(ctx, up.addr, q)
	default:
		return nil, nil, errors.New("空上游")
	}
	if err != nil {
		return nil, nil, fmt.Errorf("%s: %w", up.raw, err)
	}
	answers, cnames, err := parseDNSAnswers(msg)
	if err != nil {
		return nil, nil, fmt.Errorf("%s: %w", up.raw, err)
	}
	return answers, cnames, nil
}

func (r *resolver) queryDoH(ctx context.Context, url string, q []byte) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(q))
	if err != nil {
		return nil, err
	}
	req.Header.Set("content-type", "application/dns-message")
	req.Header.Set("accept", "application/dns-message")

	resp, err := r.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("DoH HTTP %d", resp.StatusCode)
	}
	return io.ReadAll(io.LimitReader(resp.Body, 64<<10))
}

func queryDNS(ctx context.Context, addr string, q []byte) ([]byte, error) {
	msg, err := queryDNSUDP(ctx, addr, q)
	if err == nil && !isTruncated(msg) {
		return msg, nil
	}
	return queryDNSTCP(ctx, addr, q)
}

func queryDNSUDP(ctx context.Context, addr string, q []byte) ([]byte, error) {
	var d net.Dialer
	c, err := d.DialContext(ctx, "udp", addr)
	if err != nil {
		return nil, err
	}
	defer c.Close()

	if dl, ok := ctx.Deadline(); ok {
		_ = c.SetDeadline(dl)
	}
	if _, err := c.Write(q); err != nil {
		return nil, err
	}
	buf := make([]byte, 4096)
	n, err := c.Read(buf)
	if err != nil {
		return nil, err
	}
	return buf[:n], nil
}

func queryDNSTCP(ctx context.Context, addr string, q []byte) ([]byte, error) {
	var d net.Dialer
	c, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, err
	}
	defer c.Close()

	if dl, ok := ctx.Deadline(); ok {
		_ = c.SetDeadline(dl)
	}

	packet := make([]byte, 2+len(q))
	binary.BigEndian.PutUint16(packet[:2], uint16(len(q)))
	copy(packet[2:], q)
	if _, err := c.Write(packet); err != nil {
		return nil, err
	}

	var lenBuf [2]byte
	if _, err := io.ReadFull(c, lenBuf[:]); err != nil {
		return nil, err
	}
	n := int(binary.BigEndian.Uint16(lenBuf[:]))
	if n <= 0 || n > 64<<10 {
		return nil, fmt.Errorf("DNS TCP 响应长度异常: %d", n)
	}
	buf := make([]byte, n)
	if _, err := io.ReadFull(c, buf); err != nil {
		return nil, err
	}
	return buf, nil
}

func isTruncated(msg []byte) bool {
	if len(msg) < 4 {
		return false
	}
	return msg[2]&0x02 != 0
}

var ecsRegions = []struct {
	name string
	ip   net.IP
}{
	{"日本", net.IPv4(133, 0, 0, 0)},
	{"香港", net.IPv4(203, 0, 0, 0)},
	{"新加坡", net.IPv4(165, 0, 0, 0)},
	{"美国", net.IPv4(8, 8, 8, 0)},
	{"欧洲", net.IPv4(193, 0, 0, 0)},
}

func buildDNSQuery(domain string, qtype uint16, ecs net.IP) ([]byte, error) {
	name := strings.TrimSuffix(domain, ".")
	if name == "" || len(name) > 253 {
		return nil, fmt.Errorf("非法域名: %q", domain)
	}

	buf := make([]byte, 0, 12+len(name)+6+40)
	buf = append(buf, 0, 0, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0)

	for _, label := range strings.Split(name, ".") {
		if label == "" || len(label) > 63 {
			return nil, fmt.Errorf("非法域名: %q", domain)
		}
		buf = append(buf, byte(len(label)))
		buf = append(buf, label...)
	}
	buf = append(buf, 0)                           
	buf = append(buf, byte(qtype>>8), byte(qtype)) 
	buf = append(buf, 0, 1)                        

	if ecs4 := ecs.To4(); ecs4 != nil {
		buf[11] = 1 

		ecsOpt := []byte{
			0, 8, 
			0, 7, 
			0, 1, 
			24, 
			0,  
			ecs4[0], ecs4[1], ecs4[2],
		}
		buf = append(buf, 0)          
		buf = append(buf, 0, 41)      
		buf = append(buf, 0x10, 0x00) 
		buf = append(buf, 0, 0, 0, 0) 
		buf = append(buf, 0, byte(len(ecsOpt)))
		buf = append(buf, ecsOpt...)
	}
	return buf, nil
}

func parseDNSAnswers(msg []byte) ([]dnsAnswer, []string, error) {
	if len(msg) < 12 {
		return nil, nil, errors.New("DNS 响应过短")
	}
	flags := binary.BigEndian.Uint16(msg[2:4])
	if rcode := flags & 0x000f; rcode != 0 {
		return nil, nil, fmt.Errorf("DNS rcode=%d", rcode)
	}
	qdcount := int(binary.BigEndian.Uint16(msg[4:6]))
	ancount := int(binary.BigEndian.Uint16(msg[6:8]))

	off := 12
	for i := 0; i < qdcount; i++ {
		off = skipDNSName(msg, off)
		if off < 0 || off+4 > len(msg) {
			return nil, nil, errors.New("DNS question 段越界")
		}
		off += 4
	}

	answers := make([]dnsAnswer, 0, ancount)
	var cnames []string
	for i := 0; i < ancount; i++ {
		off = skipDNSName(msg, off)
		if off < 0 || off+10 > len(msg) {
			return nil, nil, errors.New("DNS answer 段越界")
		}
		rtype := binary.BigEndian.Uint16(msg[off : off+2])
		ttl := binary.BigEndian.Uint32(msg[off+4 : off+8])
		rdlen := int(binary.BigEndian.Uint16(msg[off+8 : off+10]))
		off += 10
		if off+rdlen > len(msg) {
			return nil, nil, errors.New("DNS rdata 越界")
		}
		switch {
		case rtype == dnsTypeA && rdlen == net.IPv4len:
			ip := make(net.IP, net.IPv4len)
			copy(ip, msg[off:off+net.IPv4len])
			answers = append(answers, dnsAnswer{ip: ip.String(), ttl: ttl})
		case rtype == dnsTypeAAAA && rdlen == net.IPv6len:
			ip := make(net.IP, net.IPv6len)
			copy(ip, msg[off:off+net.IPv6len])
			answers = append(answers, dnsAnswer{ip: ip.String(), ttl: ttl, v6: true})
		case rtype == dnsTypeCNAME:
			if name, ok := readDNSName(msg, off); ok {
				cnames = append(cnames, name)
			}
		}
		off += rdlen
	}
	return answers, cnames, nil
}

func skipDNSName(msg []byte, off int) int {
	for off < len(msg) {
		l := int(msg[off])
		switch {
		case l == 0:
			return off + 1
		case l&0xc0 == 0xc0:
			if off+2 > len(msg) {
				return -1
			}
			return off + 2
		default:
			off += 1 + l
		}
	}
	return -1
}

func readDNSName(msg []byte, off int) (string, bool) {
	var sb strings.Builder
	jumps := 0
	for {
		if off < 0 || off >= len(msg) {
			return "", false
		}
		l := int(msg[off])
		if l == 0 {
			break
		}
		if l&0xc0 == 0xc0 {
			if off+2 > len(msg) {
				return "", false
			}
			ptr := int(binary.BigEndian.Uint16(msg[off:off+2]) & 0x3fff)
			jumps++
			if jumps > 8 || ptr >= len(msg) {
				return "", false
			}
			off = ptr
			continue
		}
		if l > 63 || off+1+l > len(msg) {
			return "", false
		}
		if sb.Len() > 0 {
			sb.WriteByte('.')
		}
		sb.Write(msg[off+1 : off+1+l])
		off += 1 + l
	}
	if sb.Len() == 0 {
		return "", false
	}
	return sb.String(), true
}

func dedupStrings(in []string) []string {
	seen := make(map[string]bool, len(in))
	out := make([]string, 0, len(in))
	for _, s := range in {
		if seen[s] {
			continue
		}
		seen[s] = true
		out = append(out, s)
	}
	return out
}
