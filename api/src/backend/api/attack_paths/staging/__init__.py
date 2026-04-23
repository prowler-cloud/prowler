"""
Temporary per-scan Neo4j database.

Cartography writes each scan's graph into a throw-away Neo4j database named
``db-tmp-scan-{scan_uuid}``. This is always Neo4j — Neptune is single-database
and cannot host per-scan throw-away databases. This module owns the Neo4j
driver used for temp DBs and its admin operations (CREATE / DROP DATABASE).
"""

import atexit
import logging
import threading
from contextlib import contextmanager
from typing import Any, Iterator

import neo4j
import neo4j.exceptions
from config.env import env
from django.conf import settings

from api.attack_paths.retryable_session import RetryableSession

logging.getLogger("neo4j").setLevel(logging.ERROR)
logging.getLogger("neo4j").propagate = False

SERVICE_UNAVAILABLE_MAX_RETRIES = env.int(
    "ATTACK_PATHS_SERVICE_UNAVAILABLE_MAX_RETRIES", default=3
)
CONN_ACQUISITION_TIMEOUT = env.int(
    "NEO4J_CONN_ACQUISITION_TIMEOUT", default=15
)
MAX_CONNECTION_LIFETIME = env.int(
    "NEO4J_MAX_CONNECTION_LIFETIME", default=7200
)
MAX_CONNECTION_POOL_SIZE = env.int(
    "NEO4J_MAX_CONNECTION_POOL_SIZE", default=50
)

_driver: neo4j.Driver | None = None
_lock = threading.Lock()


def _neo4j_config() -> dict:
    return settings.DATABASES["neo4j"]


def _uri() -> str:
    config = _neo4j_config()
    host = config["HOST"]
    port = config["PORT"]
    if not host or not port:
        raise RuntimeError(
            "NEO4J_HOST / NEO4J_PORT must be set to use the attack-paths "
            "temp database. Workers require Neo4j env even when the sink is Neptune."
        )
    return f"bolt://{host}:{port}"


def init_driver() -> neo4j.Driver:
    """Initialize the temp-database Neo4j driver. Idempotent."""
    global _driver
    if _driver is not None:
        return _driver

    with _lock:
        if _driver is None:
            config = _neo4j_config()
            _driver = neo4j.GraphDatabase.driver(
                _uri(),
                auth=(config["USER"], config["PASSWORD"]),
                keep_alive=True,
                max_connection_lifetime=MAX_CONNECTION_LIFETIME,
                connection_acquisition_timeout=CONN_ACQUISITION_TIMEOUT,
                max_connection_pool_size=MAX_CONNECTION_POOL_SIZE,
            )
            _driver.verify_connectivity()
            atexit.register(close_driver)

    return _driver


def get_driver() -> neo4j.Driver:
    return init_driver()


def close_driver() -> None:
    global _driver
    with _lock:
        if _driver is not None:
            try:
                _driver.close()
            finally:
                _driver = None


@contextmanager
def get_session(
    database: str | None = None,
    default_access_mode: str | None = None,
) -> Iterator[RetryableSession]:
    """Session against the Neo4j temp-database cluster. Used for temp DB sessions
    and for admin operations (CREATE / DROP DATABASE) when ``database`` is None."""
    from api.attack_paths.database import (
        ClientStatementException,
        GraphDatabaseQueryException,
        WriteQueryNotAllowedException,
    )

    READ_EXCEPTION_CODES = [
        "Neo.ClientError.Statement.AccessMode",
        "Neo.ClientError.Procedure.ProcedureNotFound",
    ]
    CLIENT_STATEMENT_EXCEPTION_PREFIX = "Neo.ClientError.Statement."

    session_wrapper: RetryableSession | None = None
    try:
        session_wrapper = RetryableSession(
            session_factory=lambda: get_driver().session(
                database=database, default_access_mode=default_access_mode
            ),
            max_retries=SERVICE_UNAVAILABLE_MAX_RETRIES,
        )
        yield session_wrapper

    except neo4j.exceptions.Neo4jError as exc:
        if (
            default_access_mode == neo4j.READ_ACCESS
            and exc.code
            and exc.code in READ_EXCEPTION_CODES
        ):
            raise WriteQueryNotAllowedException(
                message="Read query not allowed", code=READ_EXCEPTION_CODES[0]
            )

        message = exc.message if exc.message is not None else str(exc)
        if exc.code and exc.code.startswith(CLIENT_STATEMENT_EXCEPTION_PREFIX):
            raise ClientStatementException(message=message, code=exc.code)
        raise GraphDatabaseQueryException(message=message, code=exc.code)

    finally:
        if session_wrapper is not None:
            session_wrapper.close()


def create_database(database: str) -> None:
    """Create a database on the Neo4j cluster. Used for temp scan DBs."""
    with get_session() as session:
        session.run("CREATE DATABASE $database IF NOT EXISTS", {"database": database})


def drop_database(database: str) -> None:
    """Drop a database on the Neo4j cluster. Used for temp scan DBs."""
    with get_session() as session:
        session.run(f"DROP DATABASE `{database}` IF EXISTS DESTROY DATA")


def clear_cache(database: str) -> None:
    """Best-effort cache clear for a Neo4j database."""
    from api.attack_paths.database import GraphDatabaseQueryException

    try:
        with get_session(database) as session:
            session.run("CALL db.clearQueryCaches()")
    except GraphDatabaseQueryException as exc:
        logging.warning(f"Failed to clear query cache for database `{database}`: {exc}")


def run_cypher(
    database: str | None,
    cypher: str,
    parameters: dict[str, Any] | None = None,
) -> Any:
    """Execute Cypher directly without the context manager. Thin helper."""
    with get_session(database) as session:
        return session.run(cypher, parameters or {})
