package portal

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestNewCaptivePortal(t *testing.T) {
	cp := NewCaptivePortal([]byte("test-cert"), ":0", "192.168.1.1")
	if cp == nil {
		t.Fatal("NewCaptivePortal returned nil")
	}
	if string(cp.caCertPEM) != "test-cert" {
		t.Error("CA cert not set correctly")
	}
	if cp.gatewayIP != "192.168.1.1" {
		t.Error("gateway IP not set correctly")
	}
}

func TestHandlePortal(t *testing.T) {
	cp := NewCaptivePortal([]byte("test-cert"), ":0", "192.168.1.1")

	req := httptest.NewRequest("GET", "/", nil)
	w := httptest.NewRecorder()

	cp.handlePortal(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
	if !strings.Contains(w.Body.String(), "WiFi") {
		t.Error("portal page should contain 'WiFi'")
	}
	if !strings.Contains(w.Body.String(), "192.168.1.1") {
		t.Error("portal page should contain gateway IP")
	}
}

func TestHandleCertDownload(t *testing.T) {
	cp := NewCaptivePortal([]byte("test-cert-data"), ":0", "192.168.1.1")

	req := httptest.NewRequest("GET", "/cert", nil)
	w := httptest.NewRecorder()

	cp.handleCertDownload(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
	if w.Body.String() != "test-cert-data" {
		t.Error("cert download should return CA cert bytes")
	}
	if ct := w.Header().Get("Content-Type"); ct != "application/x-x509-ca-cert" {
		t.Errorf("expected application/x-x509-ca-cert, got %s", ct)
	}
	if cd := w.Header().Get("Content-Disposition"); !strings.Contains(cd, "WiFi-Profile.crt") {
		t.Errorf("expected WiFi-Profile.crt in Content-Disposition, got %s", cd)
	}
}

func TestHandleDone(t *testing.T) {
	cp := NewCaptivePortal([]byte("test"), ":0", "192.168.1.1")

	req := httptest.NewRequest("GET", "/done", nil)
	w := httptest.NewRecorder()

	cp.handleDone(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
	if !strings.Contains(w.Body.String(), "Connected") {
		t.Error("done page should contain 'Connected'")
	}
}

func TestHandleDone_MarksIPComplete(t *testing.T) {
	cp := NewCaptivePortal([]byte("test"), ":0", "192.168.1.1")

	req := httptest.NewRequest("GET", "/done", nil)
	req.RemoteAddr = "10.0.0.5:12345"
	w := httptest.NewRecorder()

	cp.handleDone(w, req)

	if !cp.installed["10.0.0.5"] {
		t.Error("IP should be marked as installed after /done")
	}
}

func TestHandleConnectivityCheck_NotInstalled(t *testing.T) {
	cp := NewCaptivePortal([]byte("test"), ":0", "192.168.1.1")

	req := httptest.NewRequest("GET", "/generate_204", nil)
	req.RemoteAddr = "10.0.0.99:12345"
	w := httptest.NewRecorder()

	cp.handleConnectivityCheck(w, req)

	if w.Code != http.StatusFound {
		t.Errorf("expected 302 redirect, got %d", w.Code)
	}
}

func TestHandleConnectivityCheck_Installed(t *testing.T) {
	cp := NewCaptivePortal([]byte("test"), ":0", "192.168.1.1")
	cp.installed["10.0.0.99"] = true

	req := httptest.NewRequest("GET", "/generate_204", nil)
	req.RemoteAddr = "10.0.0.99:12345"
	w := httptest.NewRecorder()

	cp.handleConnectivityCheck(w, req)

	if w.Code != http.StatusNoContent {
		t.Errorf("expected 204, got %d", w.Code)
	}
}

func TestGetClientIP(t *testing.T) {
	tests := []struct {
		remoteAddr string
		expected   string
	}{
		{"10.0.0.1:443", "10.0.0.1"},
		{"192.168.1.50:8080", "192.168.1.50"},
		{"[::1]:53", "::1"},
	}

	for _, tc := range tests {
		req := httptest.NewRequest("GET", "/", nil)
		req.RemoteAddr = tc.remoteAddr
		result := getClientIP(req)
		if result != tc.expected {
			t.Errorf("getClientIP(%s) = %s, want %s", tc.remoteAddr, result, tc.expected)
		}
	}
}

func TestGetClientIP_NoPort(t *testing.T) {
	req := httptest.NewRequest("GET", "/", nil)
	req.RemoteAddr = "10.0.0.1"
	result := getClientIP(req)
	if result != "10.0.0.1" {
		t.Errorf("getClientIP without port = %s, want 10.0.0.1", result)
	}
}
