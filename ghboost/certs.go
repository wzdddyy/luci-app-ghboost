package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"os"
	"sync"
	"time"
)

type CertStore struct {
	caCert    *x509.Certificate
	caKey     *ecdsa.PrivateKey
	caCertPEM []byte

	mu    sync.RWMutex
	cache map[string]*tls.Certificate
}

func NewCertStore(certPath, keyPath string) (*CertStore, error) {
	s := &CertStore{
		cache: make(map[string]*tls.Certificate),
	}

	if certPath != "" && keyPath != "" {
		if err := s.loadCA(certPath, keyPath); err == nil {
			return s, nil
		}
	}

	if err := s.generateCA(); err != nil {
		return nil, err
	}
	if certPath != "" && keyPath != "" {
		_ = s.saveCA(certPath, keyPath)
	}
	return s, nil
}

func (s *CertStore) loadCA(certPath, keyPath string) error {
	certPEM, err := os.ReadFile(certPath)
	if err != nil {
		return err
	}
	keyPEM, err := os.ReadFile(keyPath)
	if err != nil {
		return err
	}

	caTLS, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return fmt.Errorf("解析 CA 密钥对失败: %w", err)
	}
	caCert, err := x509.ParseCertificate(caTLS.Certificate[0])
	if err != nil {
		return fmt.Errorf("解析 CA 证书失败: %w", err)
	}
	caKey, ok := caTLS.PrivateKey.(*ecdsa.PrivateKey)
	if !ok {
		return fmt.Errorf("CA 私钥不是 ECDSA 类型")
	}
	s.caCert = caCert
	s.caKey = caKey
	s.caCertPEM = certPEM
	return nil
}

func (s *CertStore) generateCA() error {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return fmt.Errorf("生成 CA 私钥失败: %w", err)
	}

	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return err
	}

	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName:   "ghboost CA",
			Organization: []string{"ghboost"},
		},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().AddDate(10, 0, 0),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            1,
	}

	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return fmt.Errorf("创建 CA 证书失败: %w", err)
	}
	caCert, err := x509.ParseCertificate(der)
	if err != nil {
		return err
	}

	s.caCert = caCert
	s.caKey = key
	s.caCertPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	return nil
}

func (s *CertStore) saveCA(certPath, keyPath string) error {
	keyDER, err := x509.MarshalECPrivateKey(s.caKey)
	if err != nil {
		return err
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	if err := os.WriteFile(certPath, s.caCertPEM, 0o644); err != nil {
		return err
	}
	return os.WriteFile(keyPath, keyPEM, 0o600)
}

func (s *CertStore) GetLeafCert(domain string) (*tls.Certificate, error) {
	s.mu.RLock()
	if cert, ok := s.cache[domain]; ok {
		s.mu.RUnlock()
		return cert, nil
	}
	s.mu.RUnlock()

	s.mu.Lock()
	defer s.mu.Unlock()
	if cert, ok := s.cache[domain]; ok {
		return cert, nil
	}

	cert, err := s.generateLeafCert(domain)
	if err != nil {
		return nil, err
	}
	s.cache[domain] = cert
	return cert, nil
}

func (s *CertStore) generateLeafCert(domain string) (*tls.Certificate, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("生成叶子私钥失败: %w", err)
	}

	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, err
	}

	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName: domain,
		},
		NotBefore:   time.Now().Add(-time.Hour),
		NotAfter:    time.Now().AddDate(1, 0, 0),
		KeyUsage:    x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
	}

	if ip := net.ParseIP(domain); ip != nil {
		tmpl.IPAddresses = []net.IP{ip}
	} else {
		tmpl.DNSNames = []string{domain}
		if parts := splitDomain(domain); len(parts) >= 2 {
			tmpl.DNSNames = append(tmpl.DNSNames, "*."+joinDomain(parts[len(parts)-2:]))
		}
	}

	der, err := x509.CreateCertificate(rand.Reader, tmpl, s.caCert, &key.PublicKey, s.caKey)
	if err != nil {
		return nil, fmt.Errorf("创建叶子证书失败: %w", err)
	}

	leaf := &tls.Certificate{
		Certificate: [][]byte{der, s.caCert.Raw},
		PrivateKey:  key,
	}
	return leaf, nil
}

func (s *CertStore) ServerTLSConfig(domain string) (*tls.Config, error) {
	leaf, err := s.GetLeafCert(domain)
	if err != nil {
		return nil, err
	}
	return &tls.Config{
		Certificates: []tls.Certificate{*leaf},
		MinVersion:   tls.VersionTLS12,
	}, nil
}

func splitDomain(d string) []string {
	var parts []string
	cur := ""
	for _, r := range d {
		if r == '.' {
			parts = append(parts, cur)
			cur = ""
		} else {
			cur += string(r)
		}
	}
	if cur != "" {
		parts = append(parts, cur)
	}
	return parts
}

func joinDomain(parts []string) string {
	out := ""
	for i, p := range parts {
		if i > 0 {
			out += "."
		}
		out += p
	}
	return out
}
