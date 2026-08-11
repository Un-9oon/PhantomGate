# PhantomGate

> ⚡ Advanced Adversary-in-the-Middle (AiTM) Reverse Proxy Framework for Authorized Red Team Engagements

**PhantomGate** is a precision-engineered AiTM reverse proxy that transparently sits between a victim and a real authentication portal (Microsoft 365, GitHub, Google, etc.). It captures credentials, intercepts MFA tokens, and steals authenticated session cookies — all in real-time.

> ⚠️ **LEGAL DISCLAIMER:** This tool is designed **exclusively** for authorized penetration testing and Red Team engagements. Unauthorized use against systems you do not have explicit written permission to test is illegal under the CFAA and equivalent laws worldwide.

---

## Features

- **Transparent Reverse Proxy** — Victims see the real login page; PhantomGate sits invisibly in the middle
- **MFA Bypass** — Captures post-authentication session cookies, making MFA irrelevant
- **Phishlet System** — YAML-based target definitions for easy multi-target support
- **Credential Capture** — Real-time extraction of usernames and passwords from POST bodies
- **Session Hijacking** — Automatically captures and aggregates auth tokens for session replay
- **Operator Dashboard** — Real-time WebSocket-powered terminal UI with victim tracking
- **Lure Generator** — Creates unique tracking URLs for individual targets
- **Stealth Engine** — Strips proxy headers, spoofs server identity, removes CSP headers
- **Cross-Platform** — Single binary for Linux, Windows, and macOS

## Quick Start

```bash
# Build
make build

# List available phishlets
./bin/phantomgate --list

# Start with Microsoft 365 phishlet
sudo ./bin/phantomgate \
  --domain login-secure.com \
  --phishlet microsoft365 \
  --admin-pass MySecretPass123

# Cross-compile for all platforms
make cross
```

## Architecture

```
Victim → [HTTPS] → PhantomGate Proxy → [HTTPS] → Real Target (e.g., Microsoft 365)
                        ↓
                   Captures:
                   • Credentials (username/password)
                   • MFA session cookies
                   • Browser fingerprints
                        ↓
                   Operator Dashboard (WebSocket)
```

## Project Structure

```
PhantomGate/
├── cmd/phantomgate/main.go       # CLI entry point
├── internal/
│   ├── proxy/proxy.go            # Core AiTM reverse proxy
│   ├── proxy/tls.go              # TLS certificate generation
│   ├── capture/credentials.go    # Credential interception
│   ├── capture/sessions.go       # Session cookie hijacking
│   ├── phishlet/engine.go        # Phishlet YAML loader
│   ├── lure/generator.go         # Tracking URL generator
│   ├── store/store.go            # Data persistence
│   ├── dashboard/server.go       # Operator dashboard API
│   ├── dashboard/ui.go           # Embedded dashboard HTML
│   └── config/config.go          # Configuration system
├── phishlets/
│   ├── microsoft365.yml          # Microsoft 365 target
│   ├── github.yml                # GitHub target
│   └── google.yml                # Google Workspace target
├── config.yml                    # Default configuration
├── Makefile                      # Build targets
└── README.md
```

## Phishlets

| Phishlet | Target | Auth Tokens Captured |
|----------|--------|---------------------|
| `microsoft365` | Microsoft 365 / Azure AD | ESTSAUTH, ESTSAUTHPERSISTENT, OIDCAuthCookie |
| `github` | GitHub | user_session, dotcom_user, _gh_sess |
| `google` | Google Workspace | SID, HSID, SSID, APISID, SAPISID |

## Operator Dashboard

Access the real-time operator console at `http://localhost:8443` (default).

Features:
- Live credential capture feed
- Session hijack notifications
- Victim tracking table
- System terminal log
- Cookie export for browser import

## License

For authorized security research and penetration testing only.
