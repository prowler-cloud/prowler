from config.django.base import *  # noqa
from config.env import env

DEBUG = env.bool("DJANGO_DEBUG", default=True)
ALLOWED_HOSTS = env.list("DJANGO_ALLOWED_HOSTS", default=["*"])

# Database
default_db_name = env("POSTGRES_DB", default="prowler_db")
default_db_user = env("POSTGRES_USER", default="prowler_user")
default_db_password = env("POSTGRES_PASSWORD", default="prowler")
default_db_host = env("POSTGRES_HOST", default="postgres-db")
default_db_port = env("POSTGRES_PORT", default="5432")

DATABASES = {
    "prowler_user": {
        "ENGINE": "psqlextra.backend",
        "NAME": default_db_name,
        "USER": default_db_user,
        "PASSWORD": default_db_password,
        "HOST": default_db_host,
        "PORT": default_db_port,
    },
    "admin": {
        "ENGINE": "psqlextra.backend",
        "NAME": default_db_name,
        "USER": env("POSTGRES_ADMIN_USER", default="prowler"),
        "PASSWORD": env("POSTGRES_ADMIN_PASSWORD", default="S3cret"),
        "HOST": default_db_host,
        "PORT": default_db_port,
    },
    "replica": {
        "ENGINE": "psqlextra.backend",
        "NAME": env("POSTGRES_REPLICA_DB", default=default_db_name),
        "USER": env("POSTGRES_REPLICA_USER", default=default_db_user),
        "PASSWORD": env("POSTGRES_REPLICA_PASSWORD", default=default_db_password),
        "HOST": env("POSTGRES_REPLICA_HOST", default=default_db_host),
        "PORT": env("POSTGRES_REPLICA_PORT", default=default_db_port),
    },
    "admin_replica": {
        "ENGINE": "psqlextra.backend",
        "NAME": env("POSTGRES_REPLICA_DB", default=default_db_name),
        "USER": env("POSTGRES_ADMIN_USER", default="prowler"),
        "PASSWORD": env("POSTGRES_ADMIN_PASSWORD", default="S3cret"),
        "HOST": env("POSTGRES_REPLICA_HOST", default=default_db_host),
        "PORT": env("POSTGRES_REPLICA_PORT", default=default_db_port),
    },
    "neo4j": {
        "HOST": env.str("NEO4J_HOST", "neo4j"),
        "PORT": env.str("NEO4J_PORT", "7687"),
        "USER": env.str("NEO4J_USER", "neo4j"),
        "PASSWORD": env.str("NEO4J_PASSWORD", "neo4j_password"),
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
