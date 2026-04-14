from config.cloudfoundry import (
    build_django_databases_from_vcap_services,
    get_allowed_hosts_from_vcap_application,
    get_cors_origins_from_vcap_application,
    get_database_settings_from_vcap_services,
    get_neo4j_settings_from_environment,
    parse_environment_json,
)
from config.django.base import *  # noqa
from config.env import env

DEBUG = env.bool("DJANGO_DEBUG", default=False)
VCAP_APPLICATION = parse_environment_json(env.str("VCAP_APPLICATION", default=""))

ALLOWED_HOSTS = get_allowed_hosts_from_vcap_application(
    env.list("DJANGO_ALLOWED_HOSTS", default=["localhost", "127.0.0.1"]),
    VCAP_APPLICATION,
)
CORS_ALLOWED_ORIGINS = get_cors_origins_from_vcap_application(
    env.list(
        "DJANGO_CORS_ALLOWED_ORIGINS",
        default=["http://localhost", "http://127.0.0.1"],
    ),
    VCAP_APPLICATION,
)

# Database
# TODO Use Django database routers https://docs.djangoproject.com/en/5.0/topics/db/multi-db/#automatic-database-routing
# When not using VCAP_SERVICES (Cloud Foundry), these settings are required
# and will fail fast if missing, preventing harder-to-debug runtime errors
neo4j_settings = get_neo4j_settings_from_environment()

cloudfoundry_database_settings = get_database_settings_from_vcap_services(
    parse_environment_json(env.str("VCAP_SERVICES", default="")),
    env.str("DATABASE_URL", default=""),
)

if cloudfoundry_database_settings:
    # Cloud Foundry deployment: use VCAP_SERVICES-derived database configuration
    neo4j_settings_backup = neo4j_settings
    DATABASES = build_django_databases_from_vcap_services(
        parse_environment_json(env.str("VCAP_SERVICES", default="")),
        env.str("DATABASE_URL", default=""),
    ) or DATABASES
    DATABASES["neo4j"] = neo4j_settings_backup
else:
    # Non-Cloud Foundry deployment: require explicit database configuration
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
            "USER": env("POSTGRES_ADMIN_USER", default=default_db_user),
            "PASSWORD": env("POSTGRES_ADMIN_PASSWORD", default=default_db_password),
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
            "USER": env("POSTGRES_ADMIN_USER", default=default_db_user),
            "PASSWORD": env("POSTGRES_ADMIN_PASSWORD", default=default_db_password),
            "HOST": env("POSTGRES_REPLICA_HOST", default=default_db_host),
            "PORT": env("POSTGRES_REPLICA_PORT", default=default_db_port),
        },
        "neo4j": neo4j_settings,
    }

    DATABASES["default"] = DATABASES["prowler_user"]
