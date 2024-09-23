from config.django.base import *  # noqa
from config.env import env


DEBUG = env.bool("DJANGO_DEBUG", default=False)
ALLOWED_HOSTS = env.list("DJANGO_ALLOWED_HOSTS", default=["localhost", "127.0.0.1"])


DATABASES = {
    "default": {
        "ENGINE": "psqlextra.backend",
        "NAME": "prowler_db_test",
        "USER": env("POSTGRES_USER", default="prowler"),
        "PASSWORD": env("POSTGRES_PASSWORD", default="S3cret"),
        "HOST": env("POSTGRES_HOST", default="localhost"),
        "PORT": env("POSTGRES_PORT", default="5432"),
    },
}

DATABASE_ROUTERS = []
TESTING = True
