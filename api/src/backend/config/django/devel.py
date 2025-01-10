from config.django.base import *  # noqa
from config.env import env


DEBUG = env.bool("DJANGO_DEBUG", default=True)
ALLOWED_HOSTS = env.list("DJANGO_ALLOWED_HOSTS", default=["*"])

# Database
DATABASES = {
    "prowler_user": {
        "ENGINE": "psqlextra.backend",
        "NAME": env("POSTGRES_DB", default="prowler_db"),
        "USER": env("POSTGRES_USER", default="prowler_user"),
        "PASSWORD": env("POSTGRES_PASSWORD", default="prowler"),
        "HOST": env("POSTGRES_HOST", default="postgres-db"),
        "PORT": env("POSTGRES_PORT", default="5432"),
    },
    "admin": {
        "ENGINE": "psqlextra.backend",
        "NAME": env("POSTGRES_DB", default="prowler_db"),
        "USER": env("POSTGRES_ADMIN_USER", default="prowler"),
        "PASSWORD": env("POSTGRES_ADMIN_PASSWORD", default="S3cret"),
        "HOST": env("POSTGRES_HOST", default="postgres-db"),
        "PORT": env("POSTGRES_PORT", default="5432"),
    },
}
DATABASES["default"] = DATABASES["prowler_user"]

REST_FRAMEWORK["DEFAULT_RENDERER_CLASSES"] = tuple(  # noqa: F405
    render_class
    for render_class in REST_FRAMEWORK["DEFAULT_RENDERER_CLASSES"]  # noqa: F405
) + ("rest_framework_json_api.renderers.BrowsableAPIRenderer",)

REST_FRAMEWORK["DEFAULT_FILTER_BACKENDS"] = tuple(  # noqa: F405
    filter_backend
    for filter_backend in REST_FRAMEWORK["DEFAULT_FILTER_BACKENDS"]  # noqa: F405
    if "DjangoFilterBackend" not in filter_backend
) + ("api.filters.CustomDjangoFilterBackend",)

SECRETS_ENCRYPTION_KEY = "ZMiYVo7m4Fbe2eXXPyrwxdJss2WSalXSv3xHBcJkPl0="
