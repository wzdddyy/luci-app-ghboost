package main

import (
	"bufio"
	"fmt"
	"net"
	"os"
	"strings"
)

const (
	SNIModeDomain = "domain"
	SNIModeNone   = "none"
	SNIModeRandom = "random"
)

type domainConfig struct {
	name              string
	extra             []string
	sniMode            string
	ignoreCertMismatch bool
}

type domainTable struct {
	byIP  map[string]string
	confs map[string]*domainConfig
}

func LoadDomains(path string) (*domainTable, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open domains file: %w", err)
	}
	defer f.Close()

	t := &domainTable{
		byIP:  make(map[string]string),
		confs: make(map[string]*domainConfig),
	}

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		var comment string
		if idx := strings.Index(line, " #"); idx >= 0 {
			comment = strings.TrimSpace(line[idx+1:])
			line = strings.TrimSpace(line[:idx])
		}

		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}

		ip := net.ParseIP(fields[0])
		if ip == nil || ip.To4() == nil {
			continue
		}
		name := strings.ToLower(strings.TrimSuffix(fields[1], "."))
		if name == "" {
			continue
		}

		conf := &domainConfig{
			name:    name,
			sniMode: SNIModeDomain,
		}

		if comment != "" {
			for _, opt := range strings.Fields(comment) {
				opt = strings.TrimPrefix(opt, "#")
				if strings.HasPrefix(opt, "sni=") {
					conf.sniMode = strings.TrimPrefix(opt, "sni=")
				} else if opt == "skip-verify" || opt == "ignore-cert" {
					conf.ignoreCertMismatch = true
				}
			}
		}

		for _, item := range fields[2:] {
			extra := net.ParseIP(item)
			if extra == nil || extra.To4() == nil {
				continue
			}
			conf.extra = append(conf.extra, extra.String())
		}

		t.byIP[ip.String()] = name
		t.confs[name] = conf
	}
	return t, scanner.Err()
}

func (t *domainTable) domainOf(ip string) (string, bool) {
	if t == nil {
		return "", false
	}
	d, ok := t.byIP[ip]
	return d, ok
}

func (t *domainTable) len() int {
	if t == nil {
		return 0
	}
	return len(t.byIP)
}

func (t *domainTable) extrasOf(domain string) []string {
	if t == nil {
		return nil
	}
	if c, ok := t.confs[domain]; ok {
		return c.extra
	}
	return nil
}

func (t *domainTable) sniModeOf(domain string) string {
	if t == nil {
		return SNIModeDomain
	}
	if c, ok := t.confs[domain]; ok {
		return c.sniMode
	}
	return SNIModeDomain
}

func (t *domainTable) ignoreCertMismatchOf(domain string) bool {
	if t == nil {
		return false
	}
	if c, ok := t.confs[domain]; ok {
		return c.ignoreCertMismatch
	}
	return false
}

func (t *domainTable) pairs() [][2]string {
	if t == nil {
		return nil
	}
	out := make([][2]string, 0, len(t.byIP))
	for ip, d := range t.byIP {
		out = append(out, [2]string{ip, d})
	}
	sortFakePairs(out)
	return out
}

func (t *domainTable) names() []string {
	pairs := t.pairs()
	out := make([]string, 0, len(pairs))
	for _, p := range pairs {
		out = append(out, p[1])
	}
	return out
}
