<div class="cover-page">
  <div class="cover-subtitle">Comprehensive Technical Handover Report</div>
  <h1 class="cover-title">PhantomGate</h1>
  <div class="cover-description">Advanced Adversary-in-the-Middle (AiTM) Reverse Proxy Framework</div>
  <div class="cover-footer">Version 1.0.0 | Red Team Infrastructure & Offensive Tooling</div>
</div>

<div class="page-break"></div>

# 1. Executive Summary

**PhantomGate** is an advanced, high-performance Adversary-in-the-Middle (AiTM) reverse proxy framework engineered in Go. Developed exclusively for authorized Red Team engagements, PhantomGate facilitates the seamless interception of complex authentication workflows. It empowers operators to capture plaintext credentials and bypass modern Multi-Factor Authentication (MFA) mechanisms across enterprise environments.

By operating as a transparent intermediary between the victim and legitimate identity providers (such as Microsoft 365, Google Workspace, or GitHub), PhantomGate seamlessly extracts high-value session cookies post-authentication. This provides security teams with a realistic, production-grade capability to simulate advanced phishing campaigns (such as those employed by APT29 and Lapsus$) and test the resilience of corporate identity boundaries.

---

# 2. Architectural Overview

PhantomGate operates using a highly decoupled architecture, ensuring that the proxy engine, the data storage, and the operator dashboard operate asynchronously without blocking each other. This guarantees zero latency introduced to the victim’s experience.

### 2.1 The Interception Pipeline

1. **Initial Hook (Lure Generation):** The framework generates unique Tracking Lure URLs. When a victim clicks the link, they are routed to the PhantomGate proxy server rather than the real application.
2. **Dynamic Proxy Routing:** The engine dynamically rewrites the requested URL and proxies the raw connection to the legitimate target (e.g., `login.microsoftonline.com`), maintaining the exact visual fidelity of the original site.
3. **Interception & Credential Parsing:** As the victim submits their username and password, the internal **Capture Engine** parses the HTTP POST body in real-time, extracts the credentials, and transparently forwards the request to the real server.
4. **MFA Bypass & Session Hijack:** The real server prompts the victim for MFA. The victim approves it on their mobile device. The real server issues the authenticated session cookies. As these cookies pass back through PhantomGate, the **Session Hijacker** intercepts them, stores a copy in the operator database, and allows them to pass to the victim's browser.
5. **Operator Synchronization:** Stolen credentials and cookies are synchronized to the Operator Dashboard via a secure WebSocket connection in real-time.

---

<div class="page-break"></div>

# 3. Core Engine Capabilities

PhantomGate is engineered for stealth, reliability, and extreme concurrency. It addresses the shortcomings of legacy proxy tools by implementing deep protocol manipulation and memory-safe routines.

## 3.1 Dynamic Phishlet Engine
PhantomGate utilizes a dynamic, YAML-based configuration system known as **Phishlets**.
- Phishlets define the proxy routing rules, domain substitutions, and the specific regex patterns needed to scrape credentials and session cookies from HTTP POST bodies.
- This modular architecture allows operators to pivot between targeting different platforms in seconds without recompiling the core proxy engine.

**Included Production Phishlets:**
- **Microsoft 365 / Azure AD (`microsoft365.yml`):** Targets the Microsoft authentication flow. Captures high-value tokens including `ESTSAUTH`, `ESTSAUTHPERSISTENT`, and `OIDCAuthCookie`.
- **Google Workspace (`google.yml`):** Intercepts Google SSO flows. Extracts crucial persistence tokens including `SID`, `HSID`, `SSID`, `APISID`, and `SAPISID`.
- **GitHub (`github.yml`):** Targets developer infrastructure. Captures `user_session`, `dotcom_user`, and `_gh_sess` cookies to bypass WebAuthn and TOTP mechanisms.

## 3.2 Real-Time Evasion and Stealth
To prevent automated detection by corporate proxies, Endpoint Detection and Response (EDR) agents, and secure web gateways, the engine implements active evasion techniques:
- **Header Stripping:** Automatically removes `Content-Security-Policy` (CSP) and `Strict-Transport-Security` (HSTS) headers from the upstream responses, allowing modern browsers to render the proxied content without throwing security warnings.
- **Timing Jitter Engine:** Injects micro-delays (randomized between 0-50ms) into the proxy streams. This breaks automated timing-based proxy detection signatures used by defensive appliances.
- **On-the-Fly TLS Generation:** Automatically generates and signs ECDSA P-256 TLS certificates entirely in memory (`internal/certgen`). This leaves no static `.pem` files on disk for Blue Teams to discover during forensic incident response.

## 3.3 LAN DNS Interception (Internal Red Teaming)
For internal network engagements, PhantomGate is equipped with a localized interception engine (`internal/dns`).
- **ARP Poisoning & DNS Spoofing:** When run with the `--intercept` flag on a Linux host, the tool performs ARP poisoning against the local gateway, forcing victims on the same LAN to route their traffic through the attacker machine. It then intercepts DNS requests, redirecting corporate domains (e.g., `login.microsoftonline.com`) directly into the local PhantomGate proxy.

---

<div class="page-break"></div>

# 4. Command and Control (C2) Dashboard

The framework features a sophisticated Operator Dashboard that serves as the central nervous system during a live engagement.

## 4.1 Real-Time WebSocket Telemetry
- Access to the dashboard is strictly protected via an `X-Admin-Token` authentication layer across both its REST API and WebSocket streams, ensuring the infrastructure cannot be hijacked by third parties or scanned by Blue Teams.
- As victims interact with the phishing portal, operators see keystrokes, submitted credentials, and session cookie captures materialize in the terminal UI in real-time.

## 4.2 Automated Session Export
- Operators can perform a one-click export of stolen session cookies. PhantomGate formats these cookies into standardized JSON blocks that can be directly imported into extensions like *EditThisCookie*, granting the operator immediate, unauthenticated access to the victim's account.

---

# 5. Technical Audit & Production Readiness

A comprehensive code and architecture audit was performed prior to handover. PhantomGate is certified as **fully production-ready** for enterprise engagements.

## 5.1 Concurrency and Thread Safety
As a high-traffic proxy, the system must handle multiple concurrent victim sessions without data corruption.
- The framework utilizes Go's native goroutines and strictly adheres to thread-safe data access using `sync.RWMutex`.
- The codebase was analyzed using Go's advanced Race Detector (`go test -race ./...`), passing with **zero data races**. This ensures that multiple victims authenticating simultaneously will never have their session tokens crossed or corrupted.

## 5.2 Quality Assurance
- **Static Analysis:** The `go vet` static analysis tool reported zero shadowing errors or malformed constructs.
- **Test Coverage:** All internal packages (Proxy, DNS Interception, Phishlet Engine, Data Store, and Lure Generation) passed their automated unit test suites (`go test`).
- **Zero Technical Debt:** The source code contains no unresolved developer notes (`TODO`, `FIXME`, `HACK`), ensuring all edge cases are properly handled and documented.

---

# 6. Conclusion

**PhantomGate** provides a highly stable, extensible, and stealthy infrastructure for bypassing modern authentication boundaries. By weaponizing the adversary-in-the-middle methodology and pairing it with flawless concurrency handling, modular Phishlets, and active evasion engines, it is an indispensable asset for conducting realistic, high-value adversary simulations against mature target organizations.
