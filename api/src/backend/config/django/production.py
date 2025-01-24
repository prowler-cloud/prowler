from config.django.base import *  # noqa
from config.env import env

DEBUG = env.bool("DJANGO_DEBUG", default=False)
ALLOWED_HOSTS = env.list("DJANGO_ALLOWED_HOSTS", default=["localhost", "127.0.0.1"])

# Database
# TODO Use Django database routers https://docs.djangoproject.com/en/5.0/topics/db/multi-db/#automatic-database-routing
DATABASES = {
    "prowler_user": {
        "ENGINE": "django.db.backends.postgresql",
        "NAME": env("POSTGRES_DB"),
        "USER": env("POSTGRES_USER"),
        "PASSWORD": env("POSTGRES_PASSWORD"),
        "HOST": env("POSTGRES_HOST"),
        "PORT": env("POSTGRES_PORT"),
        "OPTIONS": {
            "pool": {
                "min_size": DB_CP_MIN_SIZE,  # noqa: F405
                "max_size": DB_CP_MAX_SIZE,  # noqa: F405
                "max_idle": DB_CP_MAX_IDLE,  # noqa: F405
                "max_lifetime": DB_CP_MAX_LIFETIME,  # noqa: F405
            }
        },
    },
    "admin": {
        "ENGINE": "psqlextra.backend",
        "NAME": env("POSTGRES_DB"),
        "USER": env("POSTGRES_ADMIN_USER"),
        "PASSWORD": env("POSTGRES_ADMIN_PASSWORD"),
        "HOST": env("POSTGRES_HOST"),
        "PORT": env("POSTGRES_PORT"),
        "OPTIONS": {
            "pool": {
                "min_size": DB_CP_MIN_SIZE,  # noqa: F405
                "max_size": DB_CP_MAX_SIZE,  # noqa: F405
                "max_idle": DB_CP_MAX_IDLE,  # noqa: F405
                "max_lifetime": DB_CP_MAX_LIFETIME,  # noqa: F405
            }
        },
    },
}
DATABASES["default"] = DATABASES["prowler_user"]
