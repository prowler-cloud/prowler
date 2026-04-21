from urllib.parse import quote

from config.env import env

_VALID_SCHEMES = {"redis", "rediss"}


def _build_celery_broker_url(
    scheme: str,
    username: str,
    password: str,
    host: str,
    port: str,
    db: str,
) -> str:
    if scheme not in _VALID_SCHEMES:
        raise ValueError(
            f"Invalid VALKEY_SCHEME '{scheme}'. Must be one of: {', '.join(sorted(_VALID_SCHEMES))}"
        )

    encoded_username = quote(username, safe="") if username else ""
    encoded_password = quote(password, safe="") if password else ""

    auth = ""
    if encoded_username and encoded_password:
        auth = f"{encoded_username}:{encoded_password}@"
    elif encoded_password:
        auth = f":{encoded_password}@"
    elif encoded_username:
        auth = f"{encoded_username}@"

    return f"{scheme}://{auth}{host}:{port}/{db}"


VALKEY_SCHEME = env("VALKEY_SCHEME", default="redis")
VALKEY_USERNAME = env("VALKEY_USERNAME", default="")
VALKEY_PASSWORD = env("VALKEY_PASSWORD", default="")
VALKEY_HOST = env("VALKEY_HOST", default="valkey")
VALKEY_PORT = env("VALKEY_PORT", default="6379")
VALKEY_DB = env("VALKEY_DB", default="0")

CELERY_BROKER_URL = _build_celery_broker_url(
    VALKEY_SCHEME,
    VALKEY_USERNAME,
    VALKEY_PASSWORD,
    VALKEY_HOST,
    VALKEY_PORT,
    VALKEY_DB,
)
CELERY_RESULT_BACKEND = "django-db"
CELERY_TASK_TRACK_STARTED = True

CELERY_BROKER_CONNECTION_RETRY_ON_STARTUP = True

CELERY_DEADLOCK_ATTEMPTS = env.int("DJANGO_CELERY_DEADLOCK_ATTEMPTS", default=5)
