package wildcard

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"time"
)

type CertManager struct {
	domain    string
	email     string
	certFile  string
	keyFile   string
}

type CertResult struct {
	CertFile   string
	KeyFile    string
	Domain     string
	ExpiresAt  time.Time
	Issuer     string
}

func NewCertManager(domain, email string) *CertManager {
	return &CertManager{
		domain:   domain,
		email:    email,
		certFile: fmt.Sprintf("/etc/phantomgate/certs/%s.pem", domain),
		keyFile:  fmt.Sprintf("/etc/phantomgate/certs/%s-key.pem", domain),
	}
}

func (c *CertManager) GenerateSelfSigned() (*CertResult, error) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("failed to generate key: %w", err)
	}
	
	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, fmt.Errorf("failed to generate serial number: %w", err)
	}
	
	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{"PhantomGate"},
			CommonName:   c.domain,
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              []string{c.domain, "*." + c.domain},
	}
	
	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		return nil, fmt.Errorf("failed to create certificate: %w", err)
	}
	
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	
	privDER, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal private key: %w", err)
	}
	
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: privDER})
	
	if err := os.MkdirAll("/etc/phantomgate/certs", 0755); err != nil {
		return nil, fmt.Errorf("failed to create certs directory: %w", err)
	}
	
	if err := os.WriteFile(c.certFile, certPEM, 0644); err != nil {
		return nil, fmt.Errorf("failed to write certificate: %w", err)
	}
	
	if err := os.WriteFile(c.keyFile, keyPEM, 0600); err != nil {
		return nil, fmt.Errorf("failed to write private key: %w", err)
	}
	
	return &CertResult{
		CertFile:  c.certFile,
		KeyFile:   c.keyFile,
		Domain:    c.domain,
		ExpiresAt: template.NotAfter,
		Issuer:    "PhantomGate Self-Signed",
	}, nil
}

func (c *CertManager) CheckExpiry() (time.Duration, error) {
	certPEM, err := os.ReadFile(c.certFile)
	if err != nil {
		return 0, fmt.Errorf("failed to read certificate: %w", err)
	}
	
	block, _ := pem.Decode(certPEM)
	if block == nil {
		return 0, fmt.Errorf("failed to decode certificate")
	}
	
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return 0, fmt.Errorf("failed to parse certificate: %w", err)
	}
	
	remaining := time.Until(cert.NotAfter)
	return remaining, nil
}

func (c *CertManager) NeedsRenewal() bool {
	remaining, err := c.CheckExpiry()
	if err != nil {
		return true
	}
	
	return remaining < 30*24*time.Hour
}
