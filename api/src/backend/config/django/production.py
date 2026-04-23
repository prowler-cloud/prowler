from config.django.base import *  # noqa
from config.env import env

DEBUG = env.bool("DJANGO_DEBUG", default=False)
ALLOWED_HOSTS = env.list("DJANGO_ALLOWED_HOSTS", default=["localhost", "127.0.0.1"])
CORS_ALLOWED_ORIGINS = env.list(
    "DJANGO_CORS_ALLOWED_ORIGINS",
    default=["http://localhost", "http://127.0.0.1"],
)

# Database
# TODO Use Django database routers https://docs.djangoproject.com/en/5.0/topics/db/multi-db/#automatic-database-routing
default_db_name = env("POSTGRES_DB")
default_db_user = env("POSTGRES_USER")
default_db_password = env("POSTGRES_PASSWORD")
default_db_host = env("POSTGRES_HOST")
default_db_port = env("POSTGRES_PORT")

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
        "USER": env("POSTGRES_ADMIN_USER"),
        "PASSWORD": env("POSTGRES_ADMIN_PASSWORD"),
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
        "USER": env("POSTGRES_ADMIN_USER"),
        "PASSWORD": env("POSTGRES_ADMIN_PASSWORD"),
        "HOST": env("POSTGRES_REPLICA_HOST", default=default_db_host),
        "PORT": env("POSTGRES_REPLICA_PORT", default=default_db_port),
    },
    # NEO4J_* fall back to empty strings so an API pod running with
    # ATTACK_PATHS_SINK_DATABASE=neptune can start without Neo4j env.
    # Workers (and Neo4j-sink API pods) must still set them; the sink/temp
    # modules validate at init time based on role.
    "neo4j": {
        "HOST": env.str("NEO4J_HOST", default=""),
        "PORT": env.str("NEO4J_PORT", default=""),
        "USER": env.str("NEO4J_USER", default=""),
        "PASSWORD": env.str("NEO4J_PASSWORD", default=""),
    },
    "neptune": {
        "WRITER_ENDPOINT": env.str("NEPTUNE_WRITER_ENDPOINT", default=""),
        "READER_ENDPOINT": env.str("NEPTUNE_READER_ENDPOINT", default=""),
        "PORT": env.str("NEPTUNE_PORT", default="8182"),
        "REGION": env.str("AWS_REGION", default=""),
    },
}

DATABASES["default"] = DATABASES["prowler_user"]
