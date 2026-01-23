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
        raise GraphDatabaseQueryException(message=exc.message, code=exc.code)

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


def drop_subgraph(database: str, root_node_label: str, root_node_id: str) -> int:
    query = """
        MATCH (a:__ROOT_NODE_LABEL__ {id: $root_node_id})
        CALL apoc.path.subgraphNodes(a, {})
        YIELD node
        DETACH DELETE node
        RETURN COUNT(node) AS deleted_nodes_count
    """.replace("__ROOT_NODE_LABEL__", root_node_label)
    parameters = {"root_node_id": root_node_id}

    with get_session(database) as session:
        result = session.run(query, parameters)

        try:
            return result.single()["deleted_nodes_count"]

        except neo4j.exceptions.ResultConsumedError:
            return 0  # As there are no nodes to delete, the result is empty


def clear_cache(database: str) -> None:
    query = "CALL db.clearQueryCaches()"

    try:
        with get_session(database) as session:
            session.run(query)

    except GraphDatabaseQueryException as exc:
        logging.warning(f"Failed to clear query cache for database `{database}`: {exc}")


# Neo4j functions related to Prowler + Cartography
DATABASE_NAME_TEMPLATE = "db-{attack_paths_scan_id}"


def get_database_name(attack_paths_scan_id: UUID) -> str:
    attack_paths_scan_id_str = str(attack_paths_scan_id).lower()
    return DATABASE_NAME_TEMPLATE.format(attack_paths_scan_id=attack_paths_scan_id_str)


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
