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
- SHA-256 hashed tokens in database (access, refresh, auth codes, session cookie tokens)
- CSRF protection with session-bound synchronizer token pattern
- Rate limiting with progressive blocking (per-IP/64 and per-account)
- Security headers (HSTS, CSP, X-Frame-Options, etc.)
- Atomic session rotation on privilege changes
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

**Prerequisites**: Go 1.26+, GCC (for SQLite CGO)

```bash
# Clone and enter directory
git clone https://github.com/cherrysoftwares/auth.git
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

The server listens on `http://localhost:5001` by default (reverse-proxied at `https://auth.gilos.org`).

## Configuration

All configuration is via environment variables (or `.env` file). See [`.env.example`](.env.example) for the full list.

| Variable | Description | Default |
|---|---|---|
| `APP_NAME` | Display name in UI and emails | `Auth` |
| `APP_ID_LABEL` | Label for user handles | `Username` |
| `ISSUER_URL` | Public base URL (OIDC issuer) | `https://auth.gilos.org` |
| `PORT` | Server port | `5001` |
| `SECURE_COOKIES` | Require HTTPS for cookies | `true` |
| `COOKIE_DOMAIN` | Cookie domain for cross-subdomain | _(empty)_ |
| `ENCRYPTION_KEY` | 64-char hex for AES-256-GCM | _(required)_ |
| `DB_PATH` | SQLite database path | `database/auth.db` |
| `RESEND_API_KEY` | Resend API key for transactional email | _(empty)_ |
| `RESEND_FROM_EMAIL` | Verified sender address (`Name <email>`) | _(empty)_ |

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
| `/auth/check-user` | GET | Check username availability |
| `/auth/login` | POST | Login (username + password + MFA) |
| `/auth/register` | POST | Register new account |
| `/auth/reset-password` | POST | Complete password reset |
| `/auth/contact/verify` | POST | Start contact OTP verification |
| `/auth/otp/send` | POST | Send/resend OTP |
| `/auth/otp/verify` | POST | Verify OTP |
| `/auth/state` | GET/POST | Auth flow state machine |
| `/auth/logout` | POST | Logout |

### Account & OAuth Management (Session & Bearer APIs)
| Endpoint | Method | Description |
|---|---|---|
| `/profile`, `/api/profile` | GET | Get profile |
| `/profile/names`, `/api/profile/names` | POST | Update name fields |
| `/sessions`, `/api/sessions` | GET | List sessions (paginated) |
| `/sessions/terminate`, `/api/sessions/terminate` | POST | Terminate a session |
| `/clients` | GET/POST | List or create OAuth clients |
| `/api/totps` | GET | List synced authenticator entries |

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
| PKCE (RFC 7636) | ✅ S256 mandatory |
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
