# Security Policy

## Supported Versions

| Version | Supported |
| ------- | --------- |
| latest  | Yes       |

## Reporting a Vulnerability

If you discover a security vulnerability in labwatch, please report it responsibly:

1. **Email**: security@labwatch.dev
2. **Do NOT** open a public GitHub issue for security vulnerabilities.

### What to include

- Description of the vulnerability
- Steps to reproduce
- Potential impact
- Suggested fix (if any)

### Response timeline

- **Acknowledgment**: within 48 hours
- **Initial assessment**: within 5 business days
- **Fix timeline**: depends on severity, but we aim for:
  - Critical: 24-48 hours
  - High: 1 week
  - Medium: 2 weeks
  - Low: next release

### Scope

- The labwatch server (Python/FastAPI)
- The labwatch agent (Go binary)
- The install script
- The Docker image

### Out of scope

- Self-hosted instances with custom modifications
- Social engineering attacks
- Denial of service (unless caused by a specific code flaw)

## Security Design

- **Agent authentication**: Bearer token per node, generated at signup
- **User authentication**: Session cookies signed with `itsdangerous` (HMAC-SHA256)
- **Admin auth (self-hosted)**: Static secret via `X-Admin-Secret` header
- **Stripe webhooks**: Verified via `stripe.Webhook.construct_event` signature check
- **CSRF protection**: Origin/Referer validation on browser-facing form endpoints
- **SSRF prevention**: DNS resolution + private/loopback/reserved IP blocking on webhook URLs
- **SQL injection**: All queries use parameterized statements
- **XSS**: Jinja2 auto-escaping enabled; `|safe` filter used only on pre-escaped content
- **Rate limiting**: Login brute-force protection (10 attempts / 5 min per IP), signup rate limiting
