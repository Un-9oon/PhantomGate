package proxy

import (
	"crypto/x509"
	"encoding/pem"
	"testing"
)

func TestGeneratePrivateKey(t *testing.T) {
	key, err := generatePrivateKey()
	if err != nil {
		t.Fatalf("generatePrivateKey failed: %v", err)
	}
	if key == nil {
		t.Fatal("expected non-nil key")
	}
}

func TestCreateSelfSignedCertPEM(t *testing.T) {
	key, err := generatePrivateKey()
	if err != nil {
		t.Fatalf("generatePrivateKey failed: %v", err)
	}

	certPEM, keyPEM, err := createSelfSignedCertPEM(key, "test.example.com")
	if err != nil {
		t.Fatalf("createSelfSignedCertPEM failed: %v", err)
	}

	if len(certPEM) == 0 {
		t.Error("expected non-empty cert PEM")
	}
	if len(keyPEM) == 0 {
		t.Error("expected non-empty key PEM")
	}

	block, _ := pem.Decode(certPEM)
	if block == nil {
		t.Fatal("failed to decode cert PEM")
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("failed to parse certificate: %v", err)
	}

	if cert.Subject.CommonName != "test.example.com" {
		t.Errorf("expected CN 'test.example.com', got %q", cert.Subject.CommonName)
	}

	foundExact := false
	foundWildcard := false
	for _, name := range cert.DNSNames {
		if name == "test.example.com" {
			foundExact = true
		}
		if name == "*.test.example.com" {
			foundWildcard = true
		}
	}
	if !foundExact {
		t.Error("expected exact domain in SAN")
	}
	if !foundWildcard {
		t.Error("expected wildcard domain in SAN")
	}
}

func TestGenerateSelfSignedCert(t *testing.T) {
	cert, err := generateSelfSignedCert("proxy.test")
	if err != nil {
		t.Fatalf("generateSelfSignedCert failed: %v", err)
	}
	if len(cert.Certificate) == 0 {
		t.Error("expected at least one certificate in chain")
	}
}
