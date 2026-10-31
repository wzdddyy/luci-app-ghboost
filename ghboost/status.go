package main

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"
)

var statusVersion = "dev"

type StatusSnapshot struct {
	Version   string    `json:"version"`
	PID       int       `json:"pid"`
	StartedAt time.Time `json:"started_at"`
	UptimeSec int64     `json:"uptime_sec"`
	Listen    string    `json:"listen"`
	Domains   int       `json:"domains"`
	MaxConns  int       `json:"max_conns"`
	Active    int       `json:"active_conns"`
	OK60   int64 `json:"ok_60s"`
	Fail60 int64 `json:"fail_60s"`
	Total  int64 `json:"total"`

	Upstreams []UpstreamStatus `json:"upstreams"`
	Hosts     []HostStatus     `json:"hosts"`
	CA        CAInfo           `json:"ca"`
	UpdatedAt time.Time        `json:"updated_at"`
}

type CAInfo struct {
	Present     bool   `json:"present"`
	Subject     string `json:"subject"`
	NotAfter    string `json:"not_after"`
	Fingerprint string `json:"fingerprint"`
}

type HostStatus struct {
	Domain string   `json:"domain"`
	FakeIP string   `json:"fake_ip"`
	IPs    []string `json:"ips"`
	Best   string   `json:"best"`
	BestMs int64    `json:"best_ms"`
	Fail   int      `json:"fail"`
	OK     int      `json:"ok"`
	Expire string `json:"expire"`
}

func (p *Proxy) snapshot() StatusSnapshot {
	now := time.Now()
	ok60, fail60, total := connStats.recent(now)

	s := StatusSnapshot{
		Version:   statusVersion,
		PID:       os.Getpid(),
		StartedAt: p.started,
		UptimeSec: int64(now.Sub(p.started).Seconds()),
		Listen:    p.cfg.Listen,
		Domains:   p.domainCount(),
		MaxConns:  p.cfg.MaxConns,
		Active:    len(p.connSem),
		OK60:      ok60,
		Fail60:    fail60,
		Total:     total,
		Upstreams: p.resolver.Status(),
		CA:        p.caInfo(),
		UpdatedAt: now,
	}

	cached := p.resolver.CachedDomains()

	hosts := make([]HostStatus, 0, p.domainCount())
	for _, pr := range p.domainPairs() {
		hosts = append(hosts, HostStatus{Domain: pr[1], FakeIP: pr[0]})
	}

	for i := range hosts {
		h := &hosts[i]
		if c, ok := cached[h.Domain]; ok {
			h.IPs = p.withExtra(h.Domain, c.IPs)
			h.Expire = c.Expire.Format(time.RFC3339)
		}
	}

	p.statMu.Lock()
	for i := range hosts {
		h := &hosts[i]
		var bestMs int64
		for _, ip := range h.IPs {
			st := p.stats[h.Domain+"|"+ip]
			if st == nil {
				continue
			}
			h.OK += st.okCnt
			h.Fail += st.failCnt
			if st.rtt > 0 && st.failAt.After(st.rttAt) {
				continue
			}
			if st.rtt > 0 && (h.Best == "" || st.rtt.Milliseconds() < bestMs) {
				h.Best = ip
				bestMs = st.rtt.Milliseconds()
			}
		}
		h.BestMs = bestMs
	}
	p.statMu.Unlock()

	s.Hosts = hosts
	return s
}

func (p *Proxy) caInfo() CAInfo {
	if p.certs == nil || p.certs.caCert == nil {
		return CAInfo{}
	}
	c := p.certs.caCert
	sum := sha256.Sum256(c.Raw)
	parts := make([]string, 0, len(sum))
	for _, b := range sum {
		parts = append(parts, fmt.Sprintf("%02X", b))
	}
	return CAInfo{
		Present:     true,
		Subject:     c.Subject.CommonName,
		NotAfter:    c.NotAfter.Format("2006-01-02"),
		Fingerprint: strings.Join(parts, ":"),
	}
}

func (p *Proxy) statusLoop() {
	if p.cfg.StatsFile == "" {
		return
	}
	t := time.NewTicker(time.Second)
	defer t.Stop()
	for {
		p.writeStatus()
		select {
		case <-p.stopCh:
			p.writeStatus()
			return
		case <-t.C:
		}
	}
}

func (p *Proxy) writeStatus() {
	if err := writeJSONAtomic(p.cfg.StatsFile, p.snapshot()); err != nil {
		logWarn("写状态快照失败: %v", err)
	}
}

func writeJSONAtomic(path string, v interface{}) error {
	data, err := json.Marshal(v)
	if err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

func unmarshalJSON(data []byte, v interface{}) error {
	return json.Unmarshal(data, v)
}
