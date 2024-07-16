from config.django.base import *  # noqa
from config.env import env


DEBUG = env.bool("DJANGO_DEBUG", default=True)
ALLOWED_HOSTS = env.list("DJANGO_ALLOWED_HOSTS", default=["*"])

# Database
DATABASES = {
    "default": {
        "ENGINE": "django.db.backends.postgresql",
        "NAME": env("POSTGRES_DB", default="prowler_db"),
        "USER": env("POSTGRES_USER", default="prowler"),
        "PASSWORD": env("POSTGRES_PASSWORD", default="S3cret"),
        "HOST": env("POSTGRES_HOST", default="postgres-db"),
        "PORT": env("POSTGRES_PORT", default="5432"),
    }
}
