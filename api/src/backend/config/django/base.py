from datetime import timedelta

from config.custom_logging import LOGGING  # noqa
from config.env import BASE_DIR, env  # noqa
from config.settings.celery import *  # noqa
from config.settings.partitions import *  # noqa

SECRET_KEY = env("SECRET_KEY", default="secret")
DEBUG = env.bool("DJANGO_DEBUG", default=False)
ALLOWED_HOSTS = ["localhost", "127.0.0.1"]

# Application definition

INSTALLED_APPS = [
    "django.contrib.admin",
    "django.contrib.auth",
    "django.contrib.contenttypes",
    "django.contrib.sessions",
    "django.contrib.messages",
    "django.contrib.staticfiles",
    "django.contrib.postgres",
    "psqlextra",
    "api",
    "rest_framework",
    "corsheaders",
    "drf_spectacular",
    "django_guid",
    "rest_framework_json_api",
    "django_celery_results",
    "django_celery_beat",
    "rest_framework_simplejwt.token_blacklist",
]

MIDDLEWARE = [
    "django_guid.middleware.guid_middleware",
    "django.middleware.security.SecurityMiddleware",
    "django.contrib.sessions.middleware.SessionMiddleware",
    "corsheaders.middleware.CorsMiddleware",
    "django.middleware.common.CommonMiddleware",
    "django.middleware.csrf.CsrfViewMiddleware",
    "django.contrib.auth.middleware.AuthenticationMiddleware",
    "django.contrib.messages.middleware.MessageMiddleware",
    "django.middleware.clickjacking.XFrameOptionsMiddleware",
    "api.middleware.APILoggingMiddleware",
]

CORS_ALLOWED_ORIGINS = ["http://localhost", "http://127.0.0.1"]

ROOT_URLCONF = "config.urls"

TEMPLATES = [
    {
        "BACKEND": "django.template.backends.django.DjangoTemplates",
        "DIRS": [],
        "APP_DIRS": True,
        "OPTIONS": {
            "context_processors": [
                "django.template.context_processors.debug",
                "django.template.context_processors.request",
                "django.contrib.auth.context_processors.auth",
                "django.contrib.messages.context_processors.messages",
            ],
        },
    },
]

REST_FRAMEWORK = {
    "DEFAULT_SCHEMA_CLASS": "drf_spectacular_jsonapi.schemas.openapi.JsonApiAutoSchema",
    "DEFAULT_AUTHENTICATION_CLASSES": (
        "rest_framework_simplejwt.authentication.JWTAuthentication",
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
    "DEFAULT_METADATA_CLASS": "rest_framework_json_api.metadata.JSONAPIMetadata",
    "DEFAULT_FILTER_BACKENDS": (
        "rest_framework_json_api.filters.QueryParameterValidationFilter",
        "rest_framework_json_api.filters.OrderingFilter",
        "rest_framework_json_api.django_filters.backends.DjangoFilterBackend",
        "rest_framework.filters.SearchFilter",
    ),
    "SEARCH_PARAM": "filter[search]",
    "TEST_REQUEST_RENDERER_CLASSES": (
        "rest_framework_json_api.renderers.JSONRenderer",
    ),
    "TEST_REQUEST_DEFAULT_FORMAT": "vnd.api+json",
    "JSON_API_UNIFORM_EXCEPTIONS": True,
}

SPECTACULAR_SETTINGS = {
    "SERVE_INCLUDE_SCHEMA": False,
    "COMPONENT_SPLIT_REQUEST": True,
    "PREPROCESSING_HOOKS": [
        "drf_spectacular_jsonapi.hooks.fix_nested_path_parameters",
    ],
}

WSGI_APPLICATION = "config.wsgi.application"

DJANGO_GUID = {
    "GUID_HEADER_NAME": "Transaction-ID",
    "VALIDATE_GUID": True,
    "RETURN_HEADER": True,
    "EXPOSE_HEADER": True,
    "INTEGRATIONS": [],
    "IGNORE_URLS": [],
    "UUID_LENGTH": 32,
}

DATABASE_ROUTERS = ["api.db_router.MainRouter"]


# Password validation
# https://docs.djangoproject.com/en/5.0/ref/settings/#auth-password-validators

AUTH_USER_MODEL = "api.User"

AUTH_PASSWORD_VALIDATORS = [
    {
        "NAME": "django.contrib.auth.password_validation.UserAttributeSimilarityValidator",
    },
    {
        "NAME": "django.contrib.auth.password_validation.MinimumLengthValidator",
        "OPTIONS": {"min_length": 12},
    },
    {
        "NAME": "api.validators.MaximumLengthValidator",
        "OPTIONS": {
            "max_length": 72,
        },
    },
    {
        "NAME": "django.contrib.auth.password_validation.CommonPasswordValidator",
    },
    {
        "NAME": "django.contrib.auth.password_validation.NumericPasswordValidator",
    },
]

SIMPLE_JWT = {
    # Token lifetime settings
    "ACCESS_TOKEN_LIFETIME": timedelta(
        minutes=env.int("DJANGO_ACCESS_TOKEN_LIFETIME", 30)
    ),
    "REFRESH_TOKEN_LIFETIME": timedelta(
        minutes=env.int("DJANGO_REFRESH_TOKEN_LIFETIME", 60 * 24)
    ),
    "ROTATE_REFRESH_TOKENS": True,
    "BLACKLIST_AFTER_ROTATION": True,
    # Algorithm and keys
    "ALGORITHM": "RS256",
    "SIGNING_KEY": env.str("DJANGO_TOKEN_SIGNING_KEY", "").replace("\\n", "\n"),
    "VERIFYING_KEY": env.str("DJANGO_TOKEN_VERIFYING_KEY", "").replace("\\n", "\n"),
    # Authorization header configuration
    "AUTH_HEADER_TYPES": ("Bearer",),
    "AUTH_HEADER_NAME": "HTTP_AUTHORIZATION",
    # Custom serializers
    "TOKEN_OBTAIN_SERIALIZER": "api.serializers.TokenSerializer",
    "TOKEN_REFRESH_SERIALIZER": "api.serializers.TokenRefreshSerializer",
    # Standard JWT claims
    "TOKEN_TYPE_CLAIM": "typ",
    "JTI_CLAIM": "jti",
    "USER_ID_FIELD": "id",
    "USER_ID_CLAIM": "sub",
    # Issuer and Audience claims, for the moment we will keep these values as default values, they may change in the future.
    "AUDIENCE": env.str("DJANGO_JWT_AUDIENCE", "https://api.prowler.com"),
    "ISSUER": env.str("DJANGO_JWT_ISSUER", "https://api.prowler.com"),
    # Additional security settings
    "UPDATE_LAST_LOGIN": True,
}

SECRETS_ENCRYPTION_KEY = env.str("DJANGO_SECRETS_ENCRYPTION_KEY", "")

# Internationalization
# https://docs.djangoproject.com/en/5.0/topics/i18n/

LANGUAGE_CODE = "en-us"
LANGUAGES = [
    ("en", "English"),
]

TIME_ZONE = "UTC"

USE_I18N = True

USE_TZ = True

# Static files (CSS, JavaScript, Images)
# https://docs.djangoproject.com/en/5.0/howto/static-files/

STATIC_URL = "static/"

# Default primary key field type
# https://docs.djangoproject.com/en/5.0/ref/settings/#default-auto-field

DEFAULT_AUTO_FIELD = "django.db.models.BigAutoField"

# Cache settings
CACHE_MAX_AGE = env.int("DJANGO_CACHE_MAX_AGE", 3600)
CACHE_STALE_WHILE_REVALIDATE = env.int("DJANGO_STALE_WHILE_REVALIDATE", 60)


TESTING = False
