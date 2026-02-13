from config.django.base import *  # noqa
from config.env import env

DEBUG = env.bool("DJANGO_DEBUG", default=False)
ALLOWED_HOSTS = env.list("DJANGO_ALLOWED_HOSTS", default=["localhost", "127.0.0.1"])


DATABASES = {
    "default": {
        "ENGINE": "psqlextra.backend",
        "NAME": "prowler_db_test",
        "USER": env("POSTGRES_USER", default="prowler_admin"),
        "PASSWORD": env("POSTGRES_PASSWORD", default="postgres"),
        "HOST": env("POSTGRES_HOST", default="localhost"),
        "PORT": env("POSTGRES_PORT", default="5432"),
    },
}

DATABASE_ROUTERS = []
TESTING = True
# Override page size for testing to a value only slightly above the current fixture count.
# We explicitly set PAGE_SIZE to 15 (round number just above fixture) to avoid masking pagination bugs, while not setting it excessively high.
# If you add more providers to the fixture, please review that the total value is below the current one and update this value if needed.
REST_FRAMEWORK["PAGE_SIZE"] = 15  # noqa: F405
SECRETS_ENCRYPTION_KEY = "ZMiYVo7m4Fbe2eXXPyrwxdJss2WSalXSv3xHBcJkPl0="

# DRF Simple API Key settings
DRF_API_KEY = {
    "FERNET_SECRET": SECRETS_ENCRYPTION_KEY,
    "API_KEY_LIFETIME": 365,
    "AUTHENTICATION_KEYWORD_HEADER": "Api-Key",
}

# JWT

SIMPLE_JWT["ALGORITHM"] = "HS256"  # noqa: F405
