package certgen

import (
	"crypto/elliptic"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
)

func TestNewPhantomCA(t *testing.T) {
	dir := t.TempDir()
	ca, err := NewPhantomCA(dir)
	if err != nil {
		t.Fatalf("NewPhantomCA failed: %v", err)
	}
	if ca.caCert == nil {
		t.Fatal("CA cert is nil")
	}
	if ca.caKey == nil {
		t.Fatal("CA key is nil")
	}
	if len(ca.caCertPEM) == 0 {
		t.Fatal("CA cert PEM is empty")
	}

	certPath := filepath.Join(dir, "ca", "ca-cert.pem")
	keyPath := filepath.Join(dir, "ca", "ca-key.pem")
	if _, err := os.Stat(certPath); os.IsNotExist(err) {
		t.Fatal("CA cert file not written")
	}
	if _, err := os.Stat(keyPath); os.IsNotExist(err) {
		t.Fatal("CA key file not written")
	}
}

func TestNewPhantomCA_LoadExisting(t *testing.T) {
	dir := t.TempDir()
	ca1, err := NewPhantomCA(dir)
	if err != nil {
		t.Fatalf("first NewPhantomCA failed: %v", err)
	}

	ca2, err := NewPhantomCA(dir)
	if err != nil {
		t.Fatalf("second NewPhantomCA failed: %v", err)
	}

	if ca1.caCert.SerialNumber.Cmp(ca2.caCert.SerialNumber) != 0 {
		t.Error("loaded CA should have same serial as saved CA")
	}
}

func TestGetCertForHost(t *testing.T) {
	dir := t.TempDir()
	ca, err := NewPhantomCA(dir)
	if err != nil {
		t.Fatalf("NewPhantomCA failed: %v", err)
	}

	cert, err := ca.GetCertForHost("login.microsoft.com")
	if err != nil {
		t.Fatalf("GetCertForHost failed: %v", err)
	}
	if cert == nil {
		t.Fatal("certificate is nil")
	}

	if len(cert.Certificate) == 0 {
		t.Fatal("certificate chain is empty")
	}

	x509Cert, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		t.Fatalf("failed to parse certificate: %v", err)
	}

	if x509Cert.Subject.CommonName != "login.microsoft.com" {
		t.Errorf("expected CN=login.microsoft.com, got %s", x509Cert.Subject.CommonName)
	}

	if len(x509Cert.DNSNames) == 0 {
		t.Error("certificate has no SAN DNS names")
	}

	if x509Cert.IsCA {
		t.Error("host certificate should not be CA")
	}
}

func TestGetCertForHost_Caching(t *testing.T) {
	dir := t.TempDir()
	ca, err := NewPhantomCA(dir)
	if err != nil {
		t.Fatalf("NewPhantomCA failed: %v", err)
	}

	cert1, _ := ca.GetCertForHost("example.com")
	cert2, _ := ca.GetCertForHost("example.com")

	if cert1 != cert2 {
		t.Error("GetCertForHost should return cached certificate for same host")
	}
}

func TestGetCertForHost_SignedByCA(t *testing.T) {
	dir := t.TempDir()
	ca, err := NewPhantomCA(dir)
	if err != nil {
		t.Fatalf("NewPhantomCA failed: %v", err)
	}

	cert, err := ca.GetCertForHost("evil.com")
	if err != nil {
		t.Fatalf("GetCertForHost failed: %v", err)
	}

	x509Cert, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		t.Fatalf("failed to parse certificate: %v", err)
	}

	pool := x509.NewCertPool()
	pool.AddCert(ca.caCert)

	opts := x509.VerifyOptions{
		Roots:     pool,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}

	if _, err := x509Cert.Verify(opts); err != nil {
		t.Errorf("certificate not signed by CA: %v", err)
	}
}

func TestGetTLSConfig(t *testing.T) {
	dir := t.TempDir()
	ca, err := NewPhantomCA(dir)
	if err != nil {
		t.Fatalf("NewPhantomCA failed: %v", err)
	}

	tlsCfg := ca.GetTLSConfig()
	if tlsCfg == nil {
		t.Fatal("GetTLSConfig returned nil")
	}
	if tlsCfg.GetCertificate == nil {
		t.Fatal("GetCertificate callback is nil")
	}

	info := &tls.ClientHelloInfo{
		ServerName: "test.example.com",
	}
	cert, err := tlsCfg.GetCertificate(info)
	if err != nil {
		t.Fatalf("GetCertificate failed: %v", err)
	}
	if cert == nil {
		t.Fatal("certificate is nil")
	}
}

func TestCACertPEM(t *testing.T) {
	dir := t.TempDir()
	ca, err := NewPhantomCA(dir)
	if err != nil {
		t.Fatalf("NewPhantomCA failed: %v", err)
	}

	pemBytes := ca.CACertPEM()
	if len(pemBytes) == 0 {
		t.Fatal("CACertPEM returned empty")
	}

	block, _ := pem.Decode(pemBytes)
	if block == nil {
		t.Fatal("failed to decode PEM")
	}
	if block.Type != "CERTIFICATE" {
		t.Errorf("expected CERTIFICATE block, got %s", block.Type)
	}
}

func TestCACertPath(t *testing.T) {
	dir := t.TempDir()
	ca, err := NewPhantomCA(dir)
	if err != nil {
		t.Fatalf("NewPhantomCA failed: %v", err)
	}

	path := ca.CACertPath()
	if path == "" {
		t.Fatal("CACertPath returned empty")
	}
	if filepath.Ext(path) != ".pem" {
		t.Errorf("expected .pem extension, got %s", filepath.Ext(path))
	}
}

func TestCAKeyIsECDSA(t *testing.T) {
	dir := t.TempDir()
	ca, err := NewPhantomCA(dir)
	if err != nil {
		t.Fatalf("NewPhantomCA failed: %v", err)
	}

	if ca.caKey.Curve != elliptic.P256() {
		t.Error("CA key should use P-256 curve")
	}
}

func TestLoadCA_InvalidCert_Regenerates(t *testing.T) {
	dir := t.TempDir()
	caDir := filepath.Join(dir, "ca")
	os.MkdirAll(caDir, 0755)

	os.WriteFile(filepath.Join(caDir, "ca-cert.pem"), []byte("not-a-cert"), 0644)
	os.WriteFile(filepath.Join(caDir, "ca-key.pem"), []byte("not-a-key"), 0600)

	ca, err := NewPhantomCA(dir)
	if err != nil {
		t.Fatalf("NewPhantomCA should regenerate on invalid CA, got error: %v", err)
	}
	if ca.caCert == nil {
		t.Error("CA cert should be regenerated")
	}
}

func TestFileExists(t *testing.T) {
	tmp := t.TempDir()
	f := filepath.Join(tmp, "test.txt")
	if fileExists(f) {
		t.Error("file should not exist yet")
	}
	os.WriteFile(f, []byte("x"), 0644)
	if !fileExists(f) {
		t.Error("file should exist now")
	}
}

func TestGetCertForHost_DifferentHosts(t *testing.T) {
	dir := t.TempDir()
	ca, err := NewPhantomCA(dir)
	if err != nil {
		t.Fatalf("NewPhantomCA failed: %v", err)
	}

	hosts := []string{"a.com", "b.com", "c.com"}
	certs := make(map[string]*tls.Certificate)

	for _, h := range hosts {
		cert, err := ca.GetCertForHost(h)
		if err != nil {
			t.Errorf("GetCertForHost(%s) failed: %v", h, err)
			continue
		}
		certs[h] = cert
	}

	// All certs should be different
	for i, h1 := range hosts {
		for _, h2 := range hosts[i+1:] {
			if certs[h1] == certs[h2] {
				t.Errorf("certs for %s and %s should be different", h1, h2)
			}
		}
	}
}

func TestGetCertForHost_Concurrent(t *testing.T) {
	dir := t.TempDir()
	ca, err := NewPhantomCA(dir)
	if err != nil {
		t.Fatalf("NewPhantomCA failed: %v", err)
	}

	done := make(chan bool, 10)
	for i := 0; i < 10; i++ {
		go func() {
			cert, err := ca.GetCertForHost("concurrent.example.com")
			if err != nil {
				t.Errorf("GetCertForHost failed: %v", err)
			}
			if cert == nil {
				t.Error("certificate is nil")
			}
			done <- true
		}()
	}
	for i := 0; i < 10; i++ {
		<-done
	}
}

func FuzzGetCertForHost(f *testing.F) {
	f.Add("example.com")
	f.Add("login.microsoft.com")
	f.Add("a.b.c.d.example.co.uk")
	f.Add("")
	f.Add("wildcard.com")

	f.Fuzz(func(t *testing.T, hostname string) {
		dir := t.TempDir()
		ca, err := NewPhantomCA(dir)
		if err != nil {
			t.Skip()
		}

		cert, err := ca.GetCertForHost(hostname)
		if err != nil {
			return
		}
		if cert == nil {
			t.Error("cert is nil without error")
		}
	})
}

func FuzzLoadCA(f *testing.F) {
	f.Add("valid-cert", "valid-key")

	f.Fuzz(func(t *testing.T, certPEM, keyPEM string) {
		dir := t.TempDir()
		caDir := filepath.Join(dir, "ca")
		os.MkdirAll(caDir, 0755)
		os.WriteFile(filepath.Join(caDir, "ca-cert.pem"), []byte(certPEM), 0644)
		os.WriteFile(filepath.Join(caDir, "ca-key.pem"), []byte(keyPEM), 0600)

		NewPhantomCA(dir)
	})
}

func BenchmarkGetCertForHost(b *testing.B) {
	dir := b.TempDir()
	ca, err := NewPhantomCA(dir)
	if err != nil {
		b.Fatalf("NewPhantomCA failed: %v", err)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ca.GetCertForHost("benchmark.example.com")
	}
}

func BenchmarkGetCertForHost_Parallel(b *testing.B) {
	dir := b.TempDir()
	ca, err := NewPhantomCA(dir)
	if err != nil {
		b.Fatalf("NewPhantomCA failed: %v", err)
	}

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			ca.GetCertForHost("bench-par.example.com")
		}
	})
}

// Ensure big.Int is used (prevents unused import)
var _ = (*big.Int)(nil)
