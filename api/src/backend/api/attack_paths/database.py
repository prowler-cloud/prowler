"""Backwards-compatible facade over the ingest and sink modules.

Historically this module owned a single Neo4j driver used for both the
cartography temp database and the per-tenant sink database. The port to AWS
Neptune split those roles: the cartography ingest (temp) database is always
Neo4j and lives in `api.attack_paths.ingest`; the sink is configurable
(Neo4j or Neptune) and lives in `api.attack_paths.sink`. This shim preserves
the public API that `tasks/` and `api/v1/views.py` already depend on, and
dispatches to the right module by database-name prefix.

A database name starting with `db-tmp-scan-` is a cartography temp DB and
routes to ingest. Everything else routes to the configured sink.
"""

from contextlib import AbstractContextManager
from typing import Any
from uuid import UUID

import neo4j  # noqa: F401 - kept for tests that patch api.attack_paths.database.neo4j
from api.attack_paths import ingest
from api.attack_paths import sink as sink_module
from config.env import env
from django.conf import (
    settings,  # noqa: F401 - kept for tests that patch ...database.settings
)

MAX_CUSTOM_QUERY_NODES = env.int("ATTACK_PATHS_MAX_CUSTOM_QUERY_NODES", default=250)

TEMP_DB_PREFIX = "db-tmp-scan-"


# Exceptions


class GraphDatabaseQueryException(Exception):
    def __init__(self, message: str, code: str | None = None) -> None:
        super().__init__(message)
        self.message = message
        self.code = code

    def __str__(self) -> str:
        if self.code:
            return f"{self.code}: {self.message}"
        return self.message


class WriteQueryNotAllowedException(GraphDatabaseQueryException):
    pass


class ClientStatementException(GraphDatabaseQueryException):
    pass


# Routing


def _is_ingest_database(database: str | None) -> bool:
    return bool(database) and database.startswith(TEMP_DB_PREFIX)


# Driver lifecycle


def init_driver() -> Any:
    """Initialize the configured sink backend.

    The ingest driver (Neo4j for cartography temp DBs) stays lazy: it is
    only initialized when a temp-DB operation actually runs, which never
    happens on API pods.
    """
    return sink_module.init()


def close_driver() -> None:
    """Close every driver held by this process."""
    sink_module.close()
    ingest.close_driver()


def get_driver() -> neo4j.Driver:
    """Return the sink backend's underlying driver.

    Only meaningful for the Neo4j sink (where the backend has a single Neo4j
    driver). On Neptune this returns the writer driver. Kept for tests and
    legacy call-sites; prefer `get_session` for new code.
    """
    backend = sink_module.get_backend()

    # Neo4jSink exposes get_driver(); NeptuneSink exposes get_writer()
    if hasattr(backend, "get_driver"):
        return backend.get_driver()

    if hasattr(backend, "get_writer"):
        return backend.get_writer()

    raise RuntimeError("Active sink backend does not expose a driver handle")


def verify_connectivity() -> None:
    """Raise if the configured graph database is unreachable on the API read path.

    Backend-agnostic entry point for the readiness probe: Neo4j verifies its
    driver, Neptune verifies the reader endpoint.
    """
    sink_module.get_backend().verify_connectivity()


def verify_scan_databases_available() -> None:
    """Raise if either graph database needed by an Attack Paths scan is unavailable."""
    errors: list[str] = []
    first_error: Exception | None = None

    try:
        ingest.get_driver().verify_connectivity()
    except Exception as exc:
        errors.append(f"ingest Neo4j: {exc}")
        first_error = exc

    try:
        get_driver().verify_connectivity()
    except Exception as exc:
        errors.append(f"sink {settings.ATTACK_PATHS_SINK_DATABASE}: {exc}")
        if first_error is None:
            first_error = exc

    if errors:
        raise RuntimeError(
            "Attack Paths graph database unavailable before scan start: "
            + "; ".join(errors)
        ) from first_error


def get_uri() -> str:
    """Return the sink URI. Retained for backwards compatibility."""
    if settings.ATTACK_PATHS_SINK_DATABASE == "neptune":
        cfg = settings.DATABASES["neptune"]
        return f"bolt+s://{cfg['WRITER_ENDPOINT']}:{cfg['PORT']}"

    cfg = settings.DATABASES["neo4j"]
    return f"bolt://{cfg['HOST']}:{cfg['PORT']}"


def get_ingest_uri() -> str:
    """Neo4j URI for the cartography temp (ingest) database, which is always
    Neo4j regardless of the configured sink."""
    return ingest.get_uri()


# Session API


def get_session(
    database: str | None = None,
    default_access_mode: str | None = None,
) -> AbstractContextManager:
    """Return a session against the right backend.

    - `database` names starting with `db-tmp-scan-` always go to ingest.
    - No database name → ingest (used for CREATE / DROP DATABASE admin ops).
    - Any other name → sink.
    """
    if _is_ingest_database(database) or database is None:
        return ingest.get_session(
            database=database, default_access_mode=default_access_mode
        )

    return sink_module.get_backend().get_session(
        database=database, default_access_mode=default_access_mode
    )


def execute_read_query(
    database: str,
    cypher: str,
    parameters: dict[str, Any] | None = None,
) -> neo4j.graph.Graph:
    """Read-only query against the sink."""
    return sink_module.get_backend().execute_read_query(database, cypher, parameters)


def create_database(database: str) -> None:
    """Create a database. Temp DBs always land on ingest (Neo4j).

    On the Neo4j sink, tenant DBs also route to ingest because both drivers
    connect to the same Neo4j cluster. On the Neptune sink, tenant DB creates
    are no-ops.
    """
    if _is_ingest_database(database):
        ingest.create_database(database)
        return

    sink_module.get_backend().create_database(database)


def drop_database(database: str) -> None:
    """Drop a database. Mirrors `create_database` routing."""
    if _is_ingest_database(database):
        ingest.drop_database(database)
        return

    sink_module.get_backend().drop_database(database)


def drop_subgraph(database: str, provider_id: str) -> int:
    return sink_module.get_backend().drop_subgraph(database, provider_id)


def has_provider_data(database: str, provider_id: str) -> bool:
    return sink_module.get_backend().has_provider_data(database, provider_id)


def clear_cache(database: str) -> None:
    if _is_ingest_database(database):
        ingest.clear_cache(database)
        return

    sink_module.get_backend().clear_cache(database)


# Name helper


def get_database_name(entity_id: str | UUID, temporary: bool = False) -> str:
    prefix = "tmp-scan" if temporary else "tenant"
    return f"db-{prefix}-{str(entity_id).lower()}"
