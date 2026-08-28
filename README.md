# Auth Server

A production-grade, open-source identity provider and authentication server. Built with Go, standards-compliant with OAuth 2.1 and OpenID Connect.

## Why Open Source?

This is the authentication server used by [Gilos](https://gilos.org) products. We open-source it so users can transparently see exactly how their data is handled, stored, and protected. You can audit the code, deploy your own instance, or contribute improvements.

## Features

### Authentication
- **Multi-step login** — Username → Password → MFA
- **Registration** with email/phone OTP verification
- **Password reset** via verified contact methods
- **Multi-factor authentication** — Email OTP, SMS OTP, TOTP (authenticator apps)
- **Account management** — Profile updates, session management, account deletion with grace period

### OAuth 2.1 / OIDC
- **Authorization Code flow** with mandatory PKCE (RFC 7636)
- **OpenID Connect Discovery** (`/.well-known/openid-configuration`)
- **JWKS endpoint** for JWT verification (`/.well-known/jwks.json`)
- **UserInfo endpoint** with standard OIDC claims
- **ID Tokens** (RS256) with nonce support
- **Token Introspection** (RFC 7662)
- **Token Revocation** (RFC 7009)
- **Refresh Token Rotation** — new refresh token on every use
- **Public & Confidential clients** — PKCE-only for public, client_secret for confidential
- **Standard scopes**: `openid`, `profile`, `email`, `phone` plus fine-grained platform scopes

### Security
- Bcrypt password hashing (configurable cost)
- AES-256-GCM encryption for TOTP secrets at rest
- SHA-256 hashed tokens in database (access, refresh, auth codes)
- CSRF protection with double-submit cookie pattern
- Rate limiting with progressive blocking (per-IP and per-account)
- Security headers (HSTS, CSP, X-Frame-Options, etc.)
- Session rotation on privilege changes
- Audit logging for all authentication events
- HttpOnly, Secure, SameSite cookies

### Developer Experience
- **Consent screen** with scope details and masked user data
- **OAuth client management** — Create, edit, delete, regenerate secrets
- **API-first** — All operations available as JSON APIs
- **i18n** — English, Uzbek, Russian (extensible)
- **SQLite** — Zero-dependency database, WAL mode for performance

## Quick Start

### Setup

**Prerequisites**: Go 1.23+, GCC (for SQLite CGO)

```bash
# Clone and enter directory
git clone https://github.com/example/auth.git
cd auth

# Install dependencies
go mod download

# Copy and configure environment
cp .env.example .env
# Edit .env — at minimum set ENCRYPTION_KEY and ISSUER_URL

# Generate encryption key
openssl rand -hex 32
# Add the output to ENCRYPTION_KEY in .env

# Run the server
go run .
```

The server starts on `https://auth.gilos.org` by default.

## Configuration

All configuration is via environment variables (or `.env` file). See [`.env.example`](.env.example) for the full list.

| Variable | Description | Default |
|---|---|---|
| `APP_NAME` | Display name in UI and emails | `Auth` |
| `APP_ID_LABEL` | Label for user identifiers | `Account ID` |
| `ISSUER_URL` | Public base URL (OIDC issuer) | `https://auth.gilos.org` |
| `PORT` | Server port | `5001` |
| `SECURE_COOKIES` | Require HTTPS for cookies | `true` |
| `COOKIE_DOMAIN` | Cookie domain for cross-subdomain | _(empty)_ |
| `ENCRYPTION_KEY` | 64-char hex for AES-256-GCM | _(required)_ |
| `DB_PATH` | SQLite database path | `database/auth.db` |

## API Endpoints

### OIDC / OAuth
| Endpoint | Method | Description |
|---|---|---|
| `/.well-known/openid-configuration` | GET | OIDC Discovery |
| `/.well-known/jwks.json` | GET | JSON Web Key Set |
| `/o/authorize` | GET/POST | Authorization endpoint |
| `/o/token` | POST | Token endpoint |
| `/o/introspect` | POST | Token introspection (RFC 7662) |
| `/o/revoke` | POST | Token revocation (RFC 7009) |
| `/api/userinfo` | GET | OIDC UserInfo |

### Authentication
| Endpoint | Method | Description |
|---|---|---|
| `/api/auth/login` | POST | Login (username + password) |
| `/api/auth/register` | POST | Register new account |
| `/api/auth/send-otp` | POST | Send/resend OTP |
| `/api/auth/verify-otp` | POST | Verify OTP |
| `/api/auth/state` | GET/POST | Auth flow state machine |
| `/api/auth/logout` | POST | Logout |

### Account Management
| Endpoint | Method | Description |
|---|---|---|
| `/api/profile` | GET | Get profile |
| `/api/profile/update` | POST | Update profile fields |
| `/api/sessions` | GET | List sessions (paginated) |
| `/api/sessions/terminate` | POST | Terminate a session |

## Architecture

```
├── config/          # Environment configuration
├── database/        # Models, migrations, session manager
├── handler/         # HTTP handlers (auth, OAuth, profile, OIDC)
│   └── client/      # OAuth client-scoped API handlers
├── i18n/            # Internationalization (en, uz, ru)
├── middleware/       # Request pipeline (auth, CORS, CSRF, rate limit)
├── static/          # CSS, fonts, images
├── templates/       # HTML templates
└── utils/           # Crypto, JWT, validation, email/SMS
```

## Standards Compliance

| Standard | Status |
|---|---|
| OAuth 2.0 (RFC 6749) | ✅ Authorization Code flow |
| OAuth 2.1 | ✅ Mandatory PKCE, no implicit flow |
| PKCE (RFC 7636) | ✅ S256 and plain |
| OpenID Connect Core | ✅ Discovery, ID Tokens, UserInfo |
| Token Introspection (RFC 7662) | ✅ |
| Token Revocation (RFC 7009) | ✅ |
| JWT (RFC 7519) | ✅ RS256 access tokens |
| JWKS (RFC 7517) | ✅ Public key endpoint |

## License

This project is licensed under the [Apache License 2.0](LICENSE). 

## Trademark Policy

The Gilos name and logos are trademarks of CHERRY SOFTWARES LLC. Please see our [Trademark Policy](TRADEMARK.md) for guidelines on how to properly use and host this software without infringing on our brand.

## Security

See [SECURITY.md](SECURITY.md) for vulnerability reporting and security design details.
