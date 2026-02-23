import atexit
import logging
import threading

from contextlib import contextmanager
from typing import Iterator
from uuid import UUID

import neo4j
import neo4j.exceptions

from django.conf import settings

from api.attack_paths.retryable_session import RetryableSession
from tasks.jobs.attack_paths.config import (
    BATCH_SIZE,
    DEPRECATED_PROVIDER_RESOURCE_LABEL,
)

# Without this Celery goes crazy with Neo4j logging
logging.getLogger("neo4j").setLevel(logging.ERROR)
logging.getLogger("neo4j").propagate = False

SERVICE_UNAVAILABLE_MAX_RETRIES = 3

# Module-level process-wide driver singleton
_driver: neo4j.Driver | None = None
_lock = threading.Lock()

# Base Neo4j functions


def get_uri() -> str:
    host = settings.DATABASES["neo4j"]["HOST"]
    port = settings.DATABASES["neo4j"]["PORT"]
    return f"bolt://{host}:{port}"


def init_driver() -> neo4j.Driver:
    global _driver
    if _driver is not None:
        return _driver

    with _lock:
        if _driver is None:
            uri = get_uri()
            config = settings.DATABASES["neo4j"]

            _driver = neo4j.GraphDatabase.driver(
                uri,
                auth=(config["USER"], config["PASSWORD"]),
                keep_alive=True,
                max_connection_lifetime=7200,
                connection_acquisition_timeout=120,
                max_connection_pool_size=50,
            )
            _driver.verify_connectivity()

            # Register cleanup handler (only runs once since we're inside the _driver is None block)
            atexit.register(close_driver)

    return _driver


def get_driver() -> neo4j.Driver:
    return init_driver()


def close_driver() -> None:  # TODO: Use it
    global _driver
    with _lock:
        if _driver is not None:
            try:
                _driver.close()

            finally:
                _driver = None


@contextmanager
def get_session(database: str | None = None) -> Iterator[RetryableSession]:
    session_wrapper: RetryableSession | None = None

    try:
        session_wrapper = RetryableSession(
            session_factory=lambda: get_driver().session(database=database),
            max_retries=SERVICE_UNAVAILABLE_MAX_RETRIES,
        )
        yield session_wrapper

    except neo4j.exceptions.Neo4jError as exc:
        message = exc.message if exc.message is not None else str(exc)
        raise GraphDatabaseQueryException(message=message, code=exc.code)

    finally:
        if session_wrapper is not None:
            session_wrapper.close()


def create_database(database: str) -> None:
    query = "CREATE DATABASE $database IF NOT EXISTS"
    parameters = {"database": database}

    with get_session() as session:
        session.run(query, parameters)


def drop_database(database: str) -> None:
    query = f"DROP DATABASE `{database}` IF EXISTS DESTROY DATA"

    with get_session() as session:
        session.run(query)


def drop_subgraph(database: str, provider_id: str) -> int:
    """
    Delete all nodes for a provider from the tenant database.

    Uses batched deletion to avoid memory issues with large graphs.
    Silently returns 0 if the database doesn't exist.
    """
    deleted_nodes = 0
    parameters = {
        "provider_id": provider_id,
        "batch_size": BATCH_SIZE,
    }

    try:
        with get_session(database) as session:
            deleted_count = 1
            while deleted_count > 0:
                result = session.run(
                    f"""
                    MATCH (n:{DEPRECATED_PROVIDER_RESOURCE_LABEL} {{provider_id: $provider_id}})
                    WITH n LIMIT $batch_size
                    DETACH DELETE n
                    RETURN COUNT(n) AS deleted_nodes_count
                    """,
                    parameters,
                )
                deleted_count = result.single().get("deleted_nodes_count", 0)
                deleted_nodes += deleted_count

    except GraphDatabaseQueryException as exc:
        if exc.code == "Neo.ClientError.Database.DatabaseNotFound":
            return 0
        raise

    return deleted_nodes


def clear_cache(database: str) -> None:
    query = "CALL db.clearQueryCaches()"

    try:
        with get_session(database) as session:
            session.run(query)

    except GraphDatabaseQueryException as exc:
        logging.warning(f"Failed to clear query cache for database `{database}`: {exc}")


# Neo4j functions related to Prowler + Cartography


def get_database_name(entity_id: str | UUID, temporary: bool = False) -> str:
    prefix = "tmp-scan" if temporary else "tenant"
    return f"db-{prefix}-{str(entity_id).lower()}"


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
