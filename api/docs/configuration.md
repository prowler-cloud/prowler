# Prowler API Configuration Documentation

This document provides comprehensive documentation for the Django configuration settings used in the Prowler API backend.

## Overview

The Prowler API uses Django's settings module pattern with environment-based configuration. Settings are organized into:

- **Base settings** (`config/django/base.py`) - Common settings for all environments
- **Development settings** (`config/django/devel.py`) - Development-specific overrides
- **Production settings** (`config/django/production.py`) - Production-specific overrides
- **Testing settings** (`config/django/testing.py`) - Test environment settings

Configuration values are loaded from environment variables using `django-environ`, with sensible defaults for development.

## Configuration Files

```
api/src/backend/config/
├── django/
│   ├── __init__.py
│   ├── base.py          # Base configuration (documented below)
│   ├── devel.py         # Development overrides
│   ├── production.py    # Production overrides
│   └── testing.py       # Testing overrides
├── settings/
│   ├── celery.py        # Celery task queue settings
│   ├── partitions.py    # Database partitioning settings
│   ├── sentry.py        # Sentry error tracking settings
│   └── social_login.py  # OAuth/SAML authentication settings
├── env.py               # Environment variable loader
├── custom_logging.py    # Logging configuration
├── celery.py            # Celery application setup
├── urls.py              # URL routing
├── wsgi.py              # WSGI application
└── asgi.py              # ASGI application
```

## Environment Variables Reference

### Core Django Settings

| Variable | Type | Default | Description |
|----------|------|---------|-------------|
| `SECRET_KEY` | string | `"secret"` | Django secret key for cryptographic signing |
| `DJANGO_DEBUG` | boolean | `False` | Enable debug mode (never in production) |

### JWT Authentication

| Variable | Type | Default | Description |
|----------|------|---------|-------------|
| `DJANGO_ACCESS_TOKEN_LIFETIME` | integer | `30` | Access token lifetime in minutes |
| `DJANGO_REFRESH_TOKEN_LIFETIME` | integer | `1440` | Refresh token lifetime in minutes (24h) |
| `DJANGO_TOKEN_SIGNING_KEY` | string | `""` | RSA private key for JWT signing (PEM format) |
| `DJANGO_TOKEN_VERIFYING_KEY` | string | `""` | RSA public key for JWT verification (PEM format) |
| `DJANGO_JWT_AUDIENCE` | string | `"https://api.prowler.com"` | JWT audience claim |
| `DJANGO_JWT_ISSUER` | string | `"https://api.prowler.com"` | JWT issuer claim |

**Note:** If signing/verifying keys are not provided, they are auto-generated at `~/.config/prowler-api/`.

### Encryption

| Variable | Type | Default | Description |
|----------|------|---------|-------------|
| `DJANGO_SECRETS_ENCRYPTION_KEY` | string | `""` | Fernet key for encrypting sensitive data |

### Rate Limiting

| Variable | Type | Default | Description |
|----------|------|---------|-------------|
| `DJANGO_THROTTLE_TOKEN_OBTAIN` | string | `None` | Rate limit for token endpoint (e.g., `"5/minute"`) |

### Caching

| Variable | Type | Default | Description |
|----------|------|---------|-------------|
| `DJANGO_CACHE_MAX_AGE` | integer | `3600` | Cache max age in seconds |
| `DJANGO_STALE_WHILE_REVALIDATE` | integer | `60` | Stale-while-revalidate window in seconds |

### Findings Configuration

| Variable | Type | Default | Description |
|----------|------|---------|-------------|
| `DJANGO_FINDINGS_MAX_DAYS_IN_RANGE` | integer | `7` | Maximum days for findings date range queries |
| `DJANGO_FINDINGS_BATCH_SIZE` | integer | `1000` | Batch size for findings export operations |

### Export Settings (S3)

| Variable | Type | Default | Description |
|----------|------|---------|-------------|
| `DJANGO_TMP_OUTPUT_DIRECTORY` | string | `"/tmp/prowler_api_output"` | Temporary directory for export files |
| `DJANGO_OUTPUT_S3_AWS_OUTPUT_BUCKET` | string | `""` | S3 bucket for exports |
| `DJANGO_OUTPUT_S3_AWS_ACCESS_KEY_ID` | string | `""` | AWS access key for S3 |
| `DJANGO_OUTPUT_S3_AWS_SECRET_ACCESS_KEY` | string | `""` | AWS secret key for S3 |
| `DJANGO_OUTPUT_S3_AWS_SESSION_TOKEN` | string | `""` | AWS session token (optional) |
| `DJANGO_OUTPUT_S3_AWS_DEFAULT_REGION` | string | `""` | AWS region for S3 bucket |

### Database Operations

| Variable | Type | Default | Description |
|----------|------|---------|-------------|
| `DJANGO_DELETION_BATCH_SIZE` | integer | `5000` | Batch size for bulk deletion operations |

## File Upload Settings

The API supports importing large scan result files (JSON/OCSF and CSV formats from Prowler CLI). These settings control the maximum file sizes accepted:

```python
# Maximum size for request body parsing (forms, JSON payloads)
DATA_UPLOAD_MAX_MEMORY_SIZE = 1024 * 1024 * 1024  # 1GB

# Maximum size for in-memory file uploads before streaming to disk
FILE_UPLOAD_MAX_MEMORY_SIZE = 1024 * 1024 * 1024  # 1GB
```

| Setting | Value | Description |
|---------|-------|-------------|
| `DATA_UPLOAD_MAX_MEMORY_SIZE` | 1GB (1,073,741,824 bytes) | Maximum size for the entire request body |
| `FILE_UPLOAD_MAX_MEMORY_SIZE` | 1GB (1,073,741,824 bytes) | Maximum size for file uploads held in memory |

**Use Case:** These limits accommodate large enterprise scan imports that may contain thousands of findings. The scan import endpoint (`POST /api/v1/scans/import`) uses these limits.

**Note:** The frontend (Next.js) also has a corresponding `serverActions.bodySizeLimit` of 1GB for server actions, matching the backend limit.

## Installed Applications

The API includes the following Django applications:

### Core Django
- `django.contrib.admin` - Admin interface
- `django.contrib.auth` - Authentication framework
- `django.contrib.contenttypes` - Content type framework
- `django.contrib.sessions` - Session framework
- `django.contrib.messages` - Messaging framework
- `django.contrib.staticfiles` - Static file handling
- `django.contrib.postgres` - PostgreSQL-specific features
- `django.contrib.sites` - Multi-site support

### Third-Party
- `rest_framework` - Django REST Framework
- `rest_framework_json_api` - JSON:API specification support
- `corsheaders` - CORS handling
- `drf_spectacular` - OpenAPI schema generation
- `drf_spectacular_jsonapi` - JSON:API schema support
- `django_guid` - Request correlation IDs
- `django_celery_results` - Celery result backend
- `django_celery_beat` - Celery periodic tasks
- `rest_framework_simplejwt` - JWT authentication
- `allauth` - Authentication providers
- `dj_rest_auth` - REST authentication endpoints
- `drf_simple_apikey` - API key authentication
- `psqlextra` - PostgreSQL extras (partitioning)

### Internal
- `api` - Prowler API application

## REST Framework Configuration

```python
REST_FRAMEWORK = {
    "DEFAULT_SCHEMA_CLASS": "drf_spectacular_jsonapi.schemas.openapi.JsonApiAutoSchema",
    "DEFAULT_AUTHENTICATION_CLASSES": (
        "api.authentication.CombinedJWTOrAPIKeyAuthentication",
    ),
    "PAGE_SIZE": 10,
    "EXCEPTION_HANDLER": "api.exceptions.custom_exception_handler",
    "DEFAULT_PAGINATION_CLASS": "drf_spectacular_jsonapi.schemas.pagination.JsonApiPageNumberPagination",
    "DEFAULT_PARSER_CLASSES": (
        "rest_framework_json_api.parsers.JSONParser",
        "rest_framework.parsers.FormParser",
        "rest_framework.parsers.MultiPartParser",
    ),
    "DEFAULT_RENDERER_CLASSES": ("api.renderers.APIJSONRenderer",),
    "DEFAULT_FILTER_BACKENDS": (
        "rest_framework_json_api.filters.QueryParameterValidationFilter",
        "rest_framework_json_api.filters.OrderingFilter",
        "rest_framework_json_api.django_filters.backends.DjangoFilterBackend",
        "rest_framework.filters.SearchFilter",
    ),
    "SEARCH_PARAM": "filter[search]",
}
```

### Key Configuration Points

| Setting | Value | Description |
|---------|-------|-------------|
| `PAGE_SIZE` | 10 | Default pagination size |
| `SEARCH_PARAM` | `filter[search]` | JSON:API compliant search parameter |
| Authentication | JWT + API Key | Combined authentication supporting both methods |
| Parsers | JSON, Form, MultiPart | Supports JSON:API, form data, and file uploads |

## JWT Configuration

The API uses RS256 (RSA with SHA-256) for JWT signing:

```python
SIMPLE_JWT = {
    "ACCESS_TOKEN_LIFETIME": timedelta(minutes=30),  # Configurable
    "REFRESH_TOKEN_LIFETIME": timedelta(minutes=1440),  # 24 hours
    "ROTATE_REFRESH_TOKENS": True,
    "BLACKLIST_AFTER_ROTATION": True,
    "ALGORITHM": "RS256",
    "AUTH_HEADER_TYPES": ("Bearer",),
    "TOKEN_TYPE_CLAIM": "typ",
    "JTI_CLAIM": "jti",
    "USER_ID_FIELD": "id",
    "USER_ID_CLAIM": "sub",
}
```

### Token Lifecycle

1. **Access Token**: Short-lived (default 30 min), used for API requests
2. **Refresh Token**: Longer-lived (default 24h), used to obtain new access tokens
3. **Rotation**: Refresh tokens are rotated on use and old tokens are blacklisted

## Password Validation

The API enforces strong password requirements:

| Validator | Requirement |
|-----------|-------------|
| `UserAttributeSimilarityValidator` | Password cannot be similar to user attributes |
| `MinimumLengthValidator` | Minimum 12 characters |
| `MaximumLengthValidator` | Maximum 72 characters |
| `CommonPasswordValidator` | Cannot be a common password |
| `NumericPasswordValidator` | Cannot be entirely numeric |
| `SpecialCharactersValidator` | At least 1 special character |
| `UppercaseValidator` | At least 1 uppercase letter |
| `LowercaseValidator` | At least 1 lowercase letter |
| `NumericValidator` | At least 1 numeric digit |

## Security Headers

```python
SECURE_CONTENT_TYPE_NOSNIFF = True
X_FRAME_OPTIONS = "DENY"
SECURE_REFERRER_POLICY = "strict-origin-when-cross-origin"
CSRF_COOKIE_SECURE = True
SESSION_COOKIE_SECURE = True
```

| Header | Value | Purpose |
|--------|-------|---------|
| `X-Content-Type-Options` | `nosniff` | Prevent MIME type sniffing |
| `X-Frame-Options` | `DENY` | Prevent clickjacking |
| `Referrer-Policy` | `strict-origin-when-cross-origin` | Control referrer information |
| Secure Cookies | `True` | Cookies only sent over HTTPS |

## Database Configuration

### Router

```python
DATABASE_ROUTERS = ["api.db_router.MainRouter"]
```

The `MainRouter` handles:
- Read/write routing for multi-database setups
- Migration routing to the `admin` database
- RLS (Row-Level Security) context management

### Custom User Model

```python
AUTH_USER_MODEL = "api.User"
```

## Request Correlation

```python
DJANGO_GUID = {
    "GUID_HEADER_NAME": "Transaction-ID",
    "VALIDATE_GUID": True,
    "RETURN_HEADER": True,
    "EXPOSE_HEADER": True,
    "UUID_LENGTH": 32,
}
```

All requests are assigned a unique transaction ID for tracing through logs and responses.

## Usage Examples

### Setting Environment Variables

```bash
# .env file
SECRET_KEY=your-production-secret-key
DJANGO_DEBUG=False
DJANGO_ACCESS_TOKEN_LIFETIME=15
DJANGO_REFRESH_TOKEN_LIFETIME=720
DJANGO_SECRETS_ENCRYPTION_KEY=your-fernet-key
DJANGO_FINDINGS_MAX_DAYS_IN_RANGE=14
```

### Loading Configuration in Code

```python
from django.conf import settings

# Access settings
max_days = settings.FINDINGS_MAX_DAYS_IN_RANGE
batch_size = settings.DJANGO_FINDINGS_BATCH_SIZE

# Check file upload limits
max_upload = settings.DATA_UPLOAD_MAX_MEMORY_SIZE  # 1GB
```

### Generating Encryption Key

```python
from cryptography.fernet import Fernet

# Generate a new Fernet key
key = Fernet.generate_key()
print(key.decode())  # Use this as DJANGO_SECRETS_ENCRYPTION_KEY
```

### Generating JWT Keys

```bash
# Generate RSA key pair
openssl genrsa -out jwt_private.pem 2048
openssl rsa -in jwt_private.pem -pubout -out jwt_public.pem

# Set as environment variables (escape newlines)
export DJANGO_TOKEN_SIGNING_KEY=$(cat jwt_private.pem | tr '\n' '\\n')
export DJANGO_TOKEN_VERIFYING_KEY=$(cat jwt_public.pem | tr '\n' '\\n')
```

## Related Documentation

- [API README](../README.md) - Setup and deployment guide
- [Models Documentation](models.md) - Database model reference
- [Partitions Documentation](partitions.md) - Table partitioning details
- [Services Documentation](../src/backend/api/services/README.md) - Business logic services
- [Parsers Documentation](../src/backend/api/parsers/README.md) - File format parsers

## Changelog

### Recent Changes

- **File Upload Limits**: Added `DATA_UPLOAD_MAX_MEMORY_SIZE` and `FILE_UPLOAD_MAX_MEMORY_SIZE` settings (1GB) to support large scan result imports via the `/api/v1/scans/import` endpoint.
