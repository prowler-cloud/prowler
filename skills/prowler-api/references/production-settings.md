# Production Settings Reference

## Django Deployment Checklist Command

```bash
cd api && poetry run python src/backend/manage.py check --deploy
```

This command checks for common deployment issues and missing security settings.

---

## Critical Settings Table

| Setting | Production Value | Risk if Wrong |
|---------|-----------------|---------------|
| `DEBUG` | `False` | Exposes stack traces, settings, SQL queries |
| `SECRET_KEY` | Env var, rotated | Session hijacking, CSRF bypass |
| `ALLOWED_HOSTS` | Explicit list | Host header attacks |
| `SECURE_SSL_REDIRECT` | `True` | Credentials sent over HTTP |
| `SESSION_COOKIE_SECURE` | `True` | Session cookies over HTTP |
| `CSRF_COOKIE_SECURE` | `True` | CSRF tokens over HTTP |
| `SECURE_HSTS_SECONDS` | `31536000` (1 year) | Downgrade attacks |
| `CONN_MAX_AGE` | `60` or higher | Connection pool exhaustion |

---

## Full Production Settings Example

```python
# settings/production.py
import environ

env = environ.Env()

# =============================================================================
# CORE SECURITY
# =============================================================================

DEBUG = False  # NEVER True in production

# Load from environment - NEVER hardcode
SECRET_KEY = env("SECRET_KEY")

# Explicit list - no wildcards
ALLOWED_HOSTS = env.list("ALLOWED_HOSTS")
# Example: ALLOWED_HOSTS=api.prowler.com,prowler.com

# =============================================================================
# HTTPS ENFORCEMENT
# =============================================================================

# Redirect all HTTP to HTTPS
SECURE_SSL_REDIRECT = True

# Trust X-Forwarded-Proto header from reverse proxy (nginx, ALB, etc.)
SECURE_PROXY_SSL_HEADER = ("HTTP_X_FORWARDED_PROTO", "https")

# =============================================================================
# SECURE COOKIES
# =============================================================================

# Only send session cookie over HTTPS
SESSION_COOKIE_SECURE = True

# Only send CSRF cookie over HTTPS
CSRF_COOKIE_SECURE = True

# Prevent JavaScript access to session cookie (XSS protection)
SESSION_COOKIE_HTTPONLY = True

# SameSite attribute for CSRF protection
CSRF_COOKIE_SAMESITE = "Strict"
SESSION_COOKIE_SAMESITE = "Strict"

# =============================================================================
# HTTP STRICT TRANSPORT SECURITY (HSTS)
# =============================================================================

# Tell browsers to always use HTTPS for this domain
SECURE_HSTS_SECONDS = 31536000  # 1 year

# Apply HSTS to all subdomains
SECURE_HSTS_INCLUDE_SUBDOMAINS = True

# Allow browser preload lists (requires domain submission)
SECURE_HSTS_PRELOAD = True

# =============================================================================
# CONTENT SECURITY
# =============================================================================

# Prevent clickjacking - deny all framing
X_FRAME_OPTIONS = "DENY"

# Prevent MIME type sniffing
SECURE_CONTENT_TYPE_NOSNIFF = True

# Enable XSS filter in older browsers
SECURE_BROWSER_XSS_FILTER = True

# =============================================================================
# DATABASE
# =============================================================================

# Connection pooling - reuse connections for 60 seconds
# Reduces connection overhead for frequent requests
CONN_MAX_AGE = 60

# For high-traffic: consider connection pooler like PgBouncer
# CONN_MAX_AGE = None  # Let PgBouncer manage connections

# =============================================================================
# LOGGING
# =============================================================================

LOGGING = {
    "version": 1,
    "disable_existing_loggers": False,
    "formatters": {
        "verbose": {
            "format": "{levelname} {asctime} {module} {process:d} {thread:d} {message}",
            "style": "{",
        },
    },
    "handlers": {
        "console": {
            "class": "logging.StreamHandler",
            "formatter": "verbose",
        },
    },
    "root": {
        "handlers": ["console"],
        "level": "INFO",  # WARNING in production to reduce noise
    },
    "loggers": {
        "django.security": {
            "handlers": ["console"],
            "level": "WARNING",
            "propagate": False,
        },
    },
}
```

---

## Environment Variables Checklist

Required environment variables for production:

```bash
# Core
SECRET_KEY=<random-50+-chars>
ALLOWED_HOSTS=api.example.com,example.com
DEBUG=False

# Database
DATABASE_URL=<your-postgres-url>
# Or individual vars:
POSTGRES_HOST=...
POSTGRES_PORT=5432
POSTGRES_DB=...
POSTGRES_USER=...
POSTGRES_PASSWORD=...

# Redis (for Celery)
REDIS_URL=redis://host:6379/0

# Optional
SENTRY_DSN=https://...@sentry.io/...
```

---

## References

- [Django Deployment Checklist](https://docs.djangoproject.com/en/5.2/howto/deployment/checklist/)
- [Django Security Settings](https://docs.djangoproject.com/en/5.2/topics/security/)
- [OWASP Secure Headers](https://owasp.org/www-project-secure-headers/)
