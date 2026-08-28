# Security Policy

## Reporting a Vulnerability

We take the security of this project seriously. If you discover a security vulnerability, please report it responsibly.

**DO NOT** open a public GitHub issue for security vulnerabilities.

### How to Report

Email your findings to: **info@gilos.email**

Please include:
- Description of the vulnerability
- Steps to reproduce
- Potential impact
- Suggested fix (if any)

### Response Timeline

- **Acknowledgment**: Within 48 hours
- **Initial assessment**: Within 5 business days
- **Fix timeline**: Depends on severity, typically within 30 days

### Scope

The following are in scope:
- Authentication bypass
- Token/session compromise
- OIDC/OAuth protocol violations
- Data exposure through API endpoints
- Cross-site scripting (XSS) in templates
- SQL injection
- CSRF bypass
- Privilege escalation

### Out of Scope

- Denial of service (DoS/DDoS)
- Social engineering
- Physical security

## Security Design

This project implements industry-standard security practices:

- **Password Storage**: bcrypt with configurable cost factor
- **Token Storage**: SHA-256 hashed (access tokens, refresh tokens, auth codes)
- **Session Security**: HttpOnly, Secure, SameSite=Lax cookies with rotation on privilege changes
- **TOTP Secrets**: AES-256-GCM encrypted at rest
- **PKCE**: Mandatory for all OAuth clients (OAuth 2.1)
- **CSRF**: Double-submit cookie pattern with constant-time comparison
- **Rate Limiting**: Per-IP and per-account with progressive blocking
- **Audit Logging**: All authentication events logged with IP, User-Agent, and request ID
