package lure

import (
	"strings"
	"testing"
)

func TestCreateLure(t *testing.T) {
	g := NewGenerator("evil.com")

	l := g.Create("microsoft365", "/", "target: john@corp.com", "")
	if l.ID == "" {
		t.Error("expected non-empty lure ID")
	}
	if !strings.HasPrefix(l.ID, "pg_") {
		t.Errorf("expected ID prefix 'pg_', got %q", l.ID)
	}
	if l.Phishlet != "microsoft365" {
		t.Errorf("expected phishlet 'microsoft365', got %q", l.Phishlet)
	}
	if l.Path != "/" {
		t.Errorf("expected path '/', got %q", l.Path)
	}
	if l.Info != "target: john@corp.com" {
		t.Errorf("unexpected info: %q", l.Info)
	}
}

func TestGetURL(t *testing.T) {
	g := NewGenerator("evil.com")
	l := g.Create("test", "/login", "test", "")

	url := g.GetURL(l)
	if !strings.HasPrefix(url, "https://login.evil.com/login?_lid=") {
		t.Errorf("unexpected URL: %s", url)
	}
	if !strings.Contains(url, l.ID) {
		t.Error("URL should contain the lure ID")
	}
}

func TestPathNormalization(t *testing.T) {
	g := NewGenerator("evil.com")

	l1 := g.Create("test", "", "test", "")
	if l1.Path != "/" {
		t.Errorf("empty path should default to '/', got %q", l1.Path)
	}

	l2 := g.Create("test", "login", "test", "")
	if l2.Path != "/login" {
		t.Errorf("path without leading / should get one, got %q", l2.Path)
	}
}

func TestTrack(t *testing.T) {
	g := NewGenerator("evil.com")
	l := g.Create("test", "/", "test", "")

	if l.Hits != 0 {
		t.Errorf("expected 0 hits, got %d", l.Hits)
	}

	tracked, ok := g.Track(l.ID)
	if !ok {
		t.Fatal("Track returned false for existing lure")
	}
	if tracked.Hits != 1 {
		t.Errorf("expected 1 hit after Track, got %d", tracked.Hits)
	}

	g.Track(l.ID)
	g.Track(l.ID)

	tracked, _ = g.Get(l.ID)
	if tracked.Hits != 3 {
		t.Errorf("expected 3 hits, got %d", tracked.Hits)
	}
}

func TestTrackNonexistent(t *testing.T) {
	g := NewGenerator("evil.com")
	_, ok := g.Track("nonexistent")
	if ok {
		t.Error("Track should return false for nonexistent lure")
	}
}

func TestDelete(t *testing.T) {
	g := NewGenerator("evil.com")
	l := g.Create("test", "/", "test", "")

	g.Delete(l.ID)

	_, ok := g.Get(l.ID)
	if ok {
		t.Error("lure should be deleted")
	}
}

func TestList(t *testing.T) {
	g := NewGenerator("evil.com")
	g.Create("test1", "/", "a", "")
	g.Create("test2", "/", "b", "")
	g.Create("test3", "/", "c", "")

	list := g.List()
	if len(list) != 3 {
		t.Errorf("expected 3 lures, got %d", len(list))
	}
}

func TestConcurrentLureOps(t *testing.T) {
	g := NewGenerator("evil.com")
	done := make(chan struct{})

	for i := 0; i < 50; i++ {
		go func() {
			defer func() { done <- struct{}{} }()
			l := g.Create("test", "/", "concurrent", "")
			g.Track(l.ID)
			g.List()
		}()
	}

	for i := 0; i < 50; i++ {
		<-done
	}

	if len(g.List()) != 50 {
		t.Errorf("expected 50 lures, got %d", len(g.List()))
	}
}
