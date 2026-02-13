# Prowler API Configuration Reference

## Settings File Structure

```
api/src/backend/config/
├── django/
│   ├── base.py               # Base settings (all environments)
│   ├── devel.py              # Development overrides
│   ├── production.py         # Production settings
│   └── testing.py            # Test settings
├── settings/
│   ├── celery.py             # Celery broker/backend config
│   ├── partitions.py         # Table partitioning settings
│   ├── sentry.py             # Error tracking + exception filtering
│   └── social_login.py       # OAuth/SAML providers
├── celery.py                 # Celery app instance + RLSTask
├── custom_logging.py         # NDJSON/Human-readable formatters
├── env.py                    # django-environ setup
└── urls.py                   # Root URL config
```

---

## REST Framework Configuration

### Complete `REST_FRAMEWORK` Settings

```python
REST_FRAMEWORK = {
    # Schema Generation (JSON:API compatible)
    "DEFAULT_SCHEMA_CLASS": "drf_spectacular_jsonapi.schemas.openapi.JsonApiAutoSchema",

    # Authentication (JWT + API Key)
    "DEFAULT_AUTHENTICATION_CLASSES": (
        "api.authentication.CombinedJWTOrAPIKeyAuthentication",
    ),

    # Pagination
    "PAGE_SIZE": 10,
    "DEFAULT_PAGINATION_CLASS": "drf_spectacular_jsonapi.schemas.pagination.JsonApiPageNumberPagination",

    # Custom exception handler (JSON:API format)
    "EXCEPTION_HANDLER": "api.exceptions.custom_exception_handler",

    # Parsers (JSON:API compatible)
    "DEFAULT_PARSER_CLASSES": (
        "rest_framework_json_api.parsers.JSONParser",
        "rest_framework.parsers.FormParser",
        "rest_framework.parsers.MultiPartParser",
    ),

    # Custom renderer with RLS context support
    "DEFAULT_RENDERER_CLASSES": ("api.renderers.APIJSONRenderer",),

    # Metadata
    "DEFAULT_METADATA_CLASS": "rest_framework_json_api.metadata.JSONAPIMetadata",

    # Filter Backends
    "DEFAULT_FILTER_BACKENDS": (
        "rest_framework_json_api.filters.QueryParameterValidationFilter",
        "rest_framework_json_api.filters.OrderingFilter",
        "rest_framework_json_api.django_filters.backends.DjangoFilterBackend",
        "rest_framework.filters.SearchFilter",
    ),

    # JSON:API search parameter
    "SEARCH_PARAM": "filter[search]",

    # Test settings
    "TEST_REQUEST_RENDERER_CLASSES": ("rest_framework_json_api.renderers.JSONRenderer",),
    "TEST_REQUEST_DEFAULT_FORMAT": "vnd.api+json",

    # Uniform exception format
    "JSON_API_UNIFORM_EXCEPTIONS": True,

    # Throttling
    "DEFAULT_THROTTLE_CLASSES": ["rest_framework.throttling.ScopedRateThrottle"],
    "DEFAULT_THROTTLE_RATES": {
        "token-obtain": env("DJANGO_THROTTLE_TOKEN_OBTAIN", default=None),
        "dj_rest_auth": None,
    },
}
```

### Throttling Configuration

| Scope | Environment Variable | Default | Format |
|-------|---------------------|---------|--------|
| `token-obtain` | `DJANGO_THROTTLE_TOKEN_OBTAIN` | `None` (disabled) | `"X/minute"`, `"X/hour"`, `"X/day"` |
| `dj_rest_auth` | N/A | `None` (disabled) | Same |

**To enable throttling:**
```bash
DJANGO_THROTTLE_TOKEN_OBTAIN="10/minute"  # Limit token endpoint to 10 requests/minute
```

---

## JWT Configuration (SIMPLE_JWT)

```python
SIMPLE_JWT = {
    # Token Lifetimes
    "ACCESS_TOKEN_LIFETIME": timedelta(minutes=30),   # DJANGO_ACCESS_TOKEN_LIFETIME
    "REFRESH_TOKEN_LIFETIME": timedelta(minutes=1440), # DJANGO_REFRESH_TOKEN_LIFETIME (24h)

    # Token Rotation
    "ROTATE_REFRESH_TOKENS": True,
    "BLACKLIST_AFTER_ROTATION": True,

    # Cryptographic Settings
    "ALGORITHM": "RS256",  # Asymmetric (requires key pair)
    "SIGNING_KEY": env.str("DJANGO_TOKEN_SIGNING_KEY", ""),
    "VERIFYING_KEY": env.str("DJANGO_TOKEN_VERIFYING_KEY", ""),

    # JWT Claims
    "TOKEN_TYPE_CLAIM": "typ",
    "JTI_CLAIM": "jti",
    "USER_ID_FIELD": "id",
    "USER_ID_CLAIM": "sub",

    # Issuer/Audience
    "AUDIENCE": env.str("DJANGO_JWT_AUDIENCE", "https://api.prowler.com"),
    "ISSUER": env.str("DJANGO_JWT_ISSUER", "https://api.prowler.com"),

    # Custom Serializers
    "TOKEN_OBTAIN_SERIALIZER": "api.serializers.TokenSerializer",
    "TOKEN_REFRESH_SERIALIZER": "api.serializers.TokenRefreshSerializer",
}
```

---

## Database Configuration

### 4-Database Architecture

```python
DATABASES = {
    "default": {...},           # Alias to prowler_user (RLS enabled)
    "prowler_user": {...},      # RLS-enabled connection
    "admin": {...},             # Admin connection (bypasses RLS)
    "replica": {...},           # Read replica (RLS enabled)
    "admin_replica": {...},     # Admin on replica
    "neo4j": {...},             # Graph database (attack paths)
}
```

### Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `POSTGRES_DB` | `prowler_db` | Database name |
| `POSTGRES_USER` | `prowler_user` | API user (RLS-constrained) |
| `POSTGRES_PASSWORD` | - | API user password |
| `POSTGRES_HOST` | `postgres-db` | Database host |
| `POSTGRES_PORT` | `5432` | Database port |
| `POSTGRES_ADMIN_USER` | `prowler` | Admin user (migrations) |
| `POSTGRES_ADMIN_PASSWORD` | - | Admin password |
| `POSTGRES_REPLICA_HOST` | - | Replica host (optional) |
| `POSTGRES_REPLICA_MAX_ATTEMPTS` | `3` | Retry attempts before fallback |
| `POSTGRES_REPLICA_RETRY_BASE_DELAY` | `0.5` | Base delay for exponential backoff |

---

## Celery Configuration

### Broker/Backend

```python
VALKEY_HOST = env("VALKEY_HOST", default="valkey")
VALKEY_PORT = env("VALKEY_PORT", default="6379")
VALKEY_DB = env("VALKEY_DB", default="0")

CELERY_BROKER_URL = f"redis://{VALKEY_HOST}:{VALKEY_PORT}/{VALKEY_DB}"
CELERY_RESULT_BACKEND = "django-db"  # Store results in PostgreSQL
CELERY_TASK_TRACK_STARTED = True
CELERY_BROKER_CONNECTION_RETRY_ON_STARTUP = True
```

### Task Visibility

| Variable | Default | Description |
|----------|---------|-------------|
| `DJANGO_BROKER_VISIBILITY_TIMEOUT` | `86400` (24h) | Task visibility timeout |
| `DJANGO_CELERY_DEADLOCK_ATTEMPTS` | `5` | Deadlock retry attempts |

---

## Partitioning Configuration

```python
PSQLEXTRA_PARTITIONING_MANAGER = "api.partitions.manager"
FINDINGS_TABLE_PARTITION_MONTHS = env.int("FINDINGS_TABLE_PARTITION_MONTHS", 1)
FINDINGS_TABLE_PARTITION_COUNT = env.int("FINDINGS_TABLE_PARTITION_COUNT", 7)
FINDINGS_TABLE_PARTITION_MAX_AGE_MONTHS = env.int("...", None)  # Optional cleanup
```

---

## Application Settings

| Variable | Default | Description |
|----------|---------|-------------|
| `DJANGO_DEBUG` | `False` | Debug mode |
| `DJANGO_ALLOWED_HOSTS` | `["localhost"]` | Allowed hosts |
| `DJANGO_CACHE_MAX_AGE` | `3600` | HTTP cache max-age |
| `DJANGO_STALE_WHILE_REVALIDATE` | `60` | Stale-while-revalidate time |
| `DJANGO_FINDINGS_MAX_DAYS_IN_RANGE` | `7` | Max days for findings date filter |
| `DJANGO_TMP_OUTPUT_DIRECTORY` | `/tmp/prowler_api_output` | Temp output directory |
| `DJANGO_FINDINGS_BATCH_SIZE` | `1000` | Batch size for findings export |
| `DJANGO_DELETION_BATCH_SIZE` | `5000` | Batch size for deletions |
| `DJANGO_LOGGING_LEVEL` | `INFO` | Log level |
| `DJANGO_LOGGING_FORMATTER` | `ndjson` | Log format (`ndjson` or `human_readable`) |

---

## Social Login (OAuth/SAML)

| Variable | Description |
|----------|-------------|
| `SOCIAL_GOOGLE_OAUTH_CLIENT_ID` | Google OAuth client ID |
| `SOCIAL_GOOGLE_OAUTH_CLIENT_SECRET` | Google OAuth secret |
| `SOCIAL_GITHUB_OAUTH_CLIENT_ID` | GitHub OAuth client ID |
| `SOCIAL_GITHUB_OAUTH_CLIENT_SECRET` | GitHub OAuth secret |

---

## Monitoring

| Variable | Description |
|----------|-------------|
| `DJANGO_SENTRY_DSN` | Sentry DSN for error tracking |

---

## Middleware Stack (Order Matters)

```python
MIDDLEWARE = [
    "django_guid.middleware.guid_middleware",        # 1. Transaction ID
    "django.middleware.security.SecurityMiddleware", # 2. Security headers
    "django.contrib.sessions.middleware.SessionMiddleware",
    "corsheaders.middleware.CorsMiddleware",         # 4. CORS (before Common)
    "django.middleware.common.CommonMiddleware",
    "django.middleware.csrf.CsrfViewMiddleware",
    "django.contrib.auth.middleware.AuthenticationMiddleware",
    "django.contrib.messages.middleware.MessageMiddleware",
    "django.middleware.clickjacking.XFrameOptionsMiddleware",
    "api.middleware.APILoggingMiddleware",           # 10. Custom API logging
    "allauth.account.middleware.AccountMiddleware",
]
```

---

## Security Headers

| Setting | Value | Description |
|---------|-------|-------------|
| `SECURE_PROXY_SSL_HEADER` | `("HTTP_X_FORWARDED_PROTO", "https")` | Trust X-Forwarded-Proto |
| `SECURE_CONTENT_TYPE_NOSNIFF` | `True` | X-Content-Type-Options: nosniff |
| `X_FRAME_OPTIONS` | `"DENY"` | Prevent framing |
| `CSRF_COOKIE_SECURE` | `True` | HTTPS-only CSRF cookie |
| `SESSION_COOKIE_SECURE` | `True` | HTTPS-only session cookie |

---

## Password Validators

| Validator | Options |
|-----------|---------|
| `UserAttributeSimilarityValidator` | Default |
| `MinimumLengthValidator` | `min_length=12` |
| `MaximumLengthValidator` | `max_length=72` (bcrypt limit) |
| `CommonPasswordValidator` | Default |
| `NumericPasswordValidator` | Default |
| `SpecialCharactersValidator` | `min_special_characters=1` |
| `UppercaseValidator` | `min_uppercase=1` |
| `LowercaseValidator` | `min_lowercase=1` |
| `NumericValidator` | `min_numeric=1` |
