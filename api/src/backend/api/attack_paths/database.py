import logging
import threading

from contextlib import contextmanager
from typing import Any, Iterator

import neo4j

from django.conf import settings
import neo4j.exceptions

from tasks.jobs.attack_paths import get_root_node_label

# Without this Celery goes crazy with Neo4j logging
logging.getLogger("neo4j").setLevel(logging.ERROR)
logging.getLogger("neo4j").propagate = False

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
                uri, auth=(config["USER"], config["PASSWORD"])
            )
            _driver.verify_connectivity()

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
def get_session(database: str | None = None) -> Iterator[neo4j.Session]:
    with get_driver().session(database=database) as session:
        yield session


def run_query(
    query: str, parameters: dict[str, Any] | None = None, database: str | None = None
) -> neo4j.Result:
    try:
        with get_session(database) as session:
            result = session.run(
                query=query,
                parameters=parameters,
            )

            return result

    except neo4j.exceptions.Neo4jError as exc:
        raise GraphDatabaseQueryException(message=exc.message, code=exc.code) from exc


def create_database(database: str) -> None:
    run_query(
        query="CREATE DATABASE $database IF NOT EXISTS",
        parameters={"database": database},
    )


def drop_database(database: str):
    # Because we use hyphens in database names, we need to use backticks and not parameters
    run_query(query=f"DROP DATABASE `{database}` IF EXISTS DESTROY DATA")


def drop_subgraph(database: str, root_node_label: str, root_node_id: str) -> int:
    query = """
        MATCH (a:__ROOT_NODE_LABEL__ {id: $root_node_id})
        CALL apoc.path.subgraphNodes(a, {})
        YIELD node
        DETACH DELETE node
        RETURN COUNT(node) AS deleted_nodes_count
    """.replace("__ROOT_NODE_LABEL__", root_node_label)

    result = run_query(
        query=query, parameters={"root_node_id": root_node_id}, database=database
    )

    try:
        deleted_nodes_count = result.single()["deleted_nodes_count"]

    except neo4j.exceptions.ResultConsumedError:
        deleted_nodes_count = 0

    return deleted_nodes_count



# Neo4j functions related to Prowler + Cartography


def get_tenant_database_name(tenant_id: str) -> str:
    prefix = settings.DATABASES["neo4j"]["DATABASE_PREFIX"]
    return f"{prefix}{tenant_id}"


def drop_tenant_database(tenant_id: str) -> bool:
    database = get_tenant_database_name(tenant_id)
    return drop_database(database)


def drop_provider_subgraph(
    tenant_id: str, provider_type: str, provider_uid: str
) -> int:
    database = get_tenant_database_name(tenant_id)
    root_node_label = get_root_node_label(provider_type)
    root_node_id = provider_uid

    return drop_subgraph(database, root_node_label, root_node_id)


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
