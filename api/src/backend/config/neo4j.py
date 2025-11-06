import threading

from contextlib import contextmanager
from typing import Iterator

import neo4j

from django.conf import settings

# Module-level process-wide driver singleton
_driver: neo4j.Driver | None = None
_lock = threading.Lock()


# Base Neo4j functions

def get_neo4j_uri() -> str:
    host = settings.DATABASES["neo4j"]["HOST"]
    port = settings.DATABASES["neo4j"]["PORT"]
    return f"bolt://{host}:{port}"


def init_neo4j_driver() -> neo4j.Driver:
    global _driver
    if _driver is not None:
        return _driver

    with _lock:
        if _driver is None:
            neo4j_uri = get_neo4j_uri()
            neo4j_config = settings.DATABASES["neo4j"]

            _driver = neo4j.GraphDatabase.driver(neo4j_uri, auth=(neo4j_config["USER"], neo4j_config["PASSWORD"]))
            _driver.verify_connectivity()

    return _driver


def get_neo4j_driver() -> neo4j.Driver:
    return init_neo4j_driver()


def close_neo4j_driver() -> None:  # TODO: Use it
    global _driver
    with _lock:
        if _driver is not None:
            try:
                _driver.close()

            finally:
                _driver = None


@contextmanager
def get_neo4j_session(database: str | None = None) -> Iterator[neo4j.Session]:
    with get_neo4j_driver().session(database=database) as session:
        yield session


def create_neo4j_database(database: str) -> None:
    with get_neo4j_session() as neo4j_session:
        neo4j_session.run(
            query="CREATE DATABASE $database IF NOT EXISTS",
            parameters={"database": database},
        )


def drop_neo4j_database(database: str) -> None:
    with get_neo4j_session() as neo4j_session:
        neo4j_session.run(
            query="DROP DATABASE $database IF EXISTS DESTROY DATA",
            parameters={"database": database},
        )


# Neo4j functions related to Prowler + Cartography

def get_neo4j_tenant_database_name(tenant_id: str) -> str:
    prefix = settings.DATABASES["neo4j"]["DATABASE_PREFIX"]
    return f"{prefix}{tenant_id}"


def drop_neo4j_tenant_database(tenant_id: str) -> None:
    database = get_neo4j_tenant_database_name(tenant_id)
    drop_neo4j_database(database)


# TODO: Remember to use this function when a tenant delete a cloud provider
def drop_neo4j_account_subgraph(database: str, root_node_label: str, account_id: str) -> None:
    query = """
        MATCH (a:__ROOT_NODE_LABEL__ {id: $account_id}})
        CALL apoc.path.subgraphNodes(a, {})
        YIELD node
        DETACH DELETE node
        RETURN COUNT(node) AS deleted_nodes_count
    """.replace("__ROOT_NODE_LABEL__", root_node_label)

    with get_neo4j_session(database) as neo4j_session:
        result = neo4j_session.run(
            query=query,
            parameters={"account_id": account_id},
        )

        return result.single()["deleted_nodes_count"]
