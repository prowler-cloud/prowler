import json
from typing import Any
from urllib.parse import urlparse


DJANGO_POSTGRES_ENGINE = "psqlextra.backend"


def parse_environment_json(raw_value: str | None) -> dict[str, Any]:
    if not raw_value:
        return {}

    try:
        parsed = json.loads(raw_value)
    except json.JSONDecodeError:
        return {}

    return parsed if isinstance(parsed, dict) else {}


def get_service_credentials(
    vcap_services: dict[str, Any], offering_names: tuple[str, ...]
) -> dict[str, Any] | None:
    for offering_name in offering_names:
        services = vcap_services.get(offering_name) or []
        if services:
            credentials = services[0].get("credentials") or {}
            if isinstance(credentials, dict):
                return credentials

    return None


def _parse_database_url(database_url: str) -> dict[str, Any] | None:
    parsed = urlparse(database_url)
    if not parsed.scheme or not parsed.hostname:
        return None

    database_name = parsed.path.lstrip("/")
    if not database_name:
        return None

    return {
        "NAME": database_name,
        "USER": parsed.username or "",
        "PASSWORD": parsed.password or "",
        "HOST": parsed.hostname,
        "PORT": str(parsed.port or 5432),
        "OPTIONS": {"sslmode": "require"},
    }


def get_database_settings_from_vcap_services(
    vcap_services: dict[str, Any],
    database_url: str | None = None,
) -> dict[str, dict[str, Any]] | None:
    credentials = get_service_credentials(vcap_services, ("aws-rds",))
    primary_url = database_url or (credentials or {}).get("uri")
    if not primary_url:
        return None

    primary_settings = _parse_database_url(primary_url)
    if not primary_settings:
        return None

    replica_url = (credentials or {}).get("replica_uri")
    replica_settings = _parse_database_url(replica_url) if replica_url else None

    database_settings = {
        "prowler_user": primary_settings,
        "admin": primary_settings.copy(),
    }

    if replica_settings:
        database_settings["replica"] = replica_settings
        database_settings["admin_replica"] = replica_settings.copy()

    return database_settings


def build_django_databases_from_vcap_services(
    vcap_services: dict[str, Any],
    database_url: str | None = None,
) -> dict[str, dict[str, Any]] | None:
    alias_settings = get_database_settings_from_vcap_services(
        vcap_services,
        database_url,
    )
    if not alias_settings:
        return None

    databases = {
        "default": {
            "ENGINE": DJANGO_POSTGRES_ENGINE,
            **alias_settings["prowler_user"],
        },
        "prowler_user": {
            "ENGINE": DJANGO_POSTGRES_ENGINE,
            **alias_settings["prowler_user"],
        },
        "admin": {
            "ENGINE": DJANGO_POSTGRES_ENGINE,
            **alias_settings["admin"],
        },
    }

    if "replica" in alias_settings:
        databases["replica"] = {
            "ENGINE": DJANGO_POSTGRES_ENGINE,
            **alias_settings["replica"],
        }

    if "admin_replica" in alias_settings:
        databases["admin_replica"] = {
            "ENGINE": DJANGO_POSTGRES_ENGINE,
            **alias_settings["admin_replica"],
        }

    return databases


def get_redis_settings_from_vcap_services(
    vcap_services: dict[str, Any],
) -> dict[str, str] | None:
    credentials = get_service_credentials(vcap_services, ("aws-elasticache-redis",))
    if not credentials:
        return None

    redis_url = credentials.get("uri")
    if redis_url:
        parsed = urlparse(redis_url)
        if parsed.scheme and parsed.hostname:
            database_number = parsed.path.lstrip("/") or "0"
            return {
                "scheme": parsed.scheme,
                "username": parsed.username or "",
                "password": parsed.password or "",
                "host": parsed.hostname,
                "port": str(parsed.port or 6379),
                "db": database_number,
            }

    host = credentials.get("host")
    if not host:
        return None

    return {
        "scheme": credentials.get("scheme", "redis"),
        "username": credentials.get("username", ""),
        "password": credentials.get("password", ""),
        "host": host,
        "port": str(credentials.get("port", 6379)),
        "db": str(credentials.get("db", 0)),
    }


def get_allowed_hosts_from_vcap_application(
    default_hosts: list[str], vcap_application: dict[str, Any]
) -> list[str]:
    application_uris = vcap_application.get("application_uris") or []
    merged_hosts = list(default_hosts)

    for host in application_uris:
        if host not in merged_hosts:
            merged_hosts.append(host)

    return merged_hosts


def get_cors_origins_from_vcap_application(
    default_origins: list[str], vcap_application: dict[str, Any]
) -> list[str]:
    application_uris = vcap_application.get("application_uris") or []
    merged_origins = list(default_origins)

    for host in application_uris:
        origin = f"https://{host}"
        if origin not in merged_origins:
            merged_origins.append(origin)

    return merged_origins