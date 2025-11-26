import logging
import threading

from contextlib import contextmanager
from typing import Iterator
from uuid import UUID

import neo4j
import shortuuid

from django.conf import settings

import neo4j.exceptions

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
    try:
        with get_driver().session(database=database) as session:
            yield session

    except neo4j.exceptions.Neo4jError as exc:
        raise GraphDatabaseQueryException(message=exc.message, code=exc.code)


def create_database(database: str) -> None:
    query = "CREATE DATABASE $database IF NOT EXISTS"
    parameters = {"database": database}

    with get_session() as session:
        session.run(query, parameters)


def drop_database(database: str):
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


# Neo4j functions related to Prowler + Cartography
TENANT_DATABASE_NAME_PREFIX_TEMPLATE = "db-{tenant_id}-"
TENANT_PROVIDER_DATABASE_NAME_PREFIX_TEMPLATE = (
    TENANT_DATABASE_NAME_PREFIX_TEMPLATE + "{provider_id}-"
)
TENANT_PROVIDER_SCAN_DATABASE_NAME_TEMPLATE = (
    TENANT_PROVIDER_DATABASE_NAME_PREFIX_TEMPLATE + "{partial_attack_paths_scan_id}"
)


def get_shortuuid(id: str | UUID) -> str:
    if isinstance(id, UUID):
        return shortuuid.encode(id)

    return shortuuid.encode(UUID(id))


def get_tenant_provider_scan_database_name(
    tenant_id: UUID, provider_id: UUID, attack_paths_scan_id: UUID
) -> str:
    """
    Neo4j database names have a maximum of 63 characters:
      https://neo4j.com/docs/operations-manual/current/database-administration/standard-databases/naming-databases/

    `shourtuuid` always generates 22 characters:
     https://github.com/skorokithakis/shortuuid/tree/6843c128cb334c272954cce8f1dce1e9f9bf4054?tab=readme-ov-file#usage

    So, `db-{tenant_id}-{provider_id}-` would be:
      2 + 1 + 22 + 1 + 22 + 1 = 49 characters
      63 - 49 = 14 characters left for uniqueness

    With 14 characters we have more than enough uniqueness for our use case:
      https://github.com/oittaa/uuid6-python/tree/89351300ab5c75a158038d1f4e2f586d4ae9120e?tab=readme-ov-file#uuidv7-field-and-bit-layout
    """
    short_tenant_id = get_shortuuid(tenant_id)
    short_provider_id = get_shortuuid(provider_id)
    partial_short_attack_paths_scan_id = get_shortuuid(attack_paths_scan_id)[:14]

    return TENANT_PROVIDER_SCAN_DATABASE_NAME_TEMPLATE.format(
        tenant_id=short_tenant_id,
        provider_id=short_provider_id,
        partial_attack_paths_scan_id=partial_short_attack_paths_scan_id,
    )


# TODO: Fix the necesity of `toLower` with databases with names as `db-{lower_case_attack_paths_scan_id}`
def get_databases_by_prefix(prefix: str) -> list[str]:
    query = f"""
        SHOW DATABASES
        YIELD name
        WHERE name STARTS WITH toLower('{prefix}')
        RETURN name
    """

    with get_session() as session:
        result = session.run(query)
        result_rows = result.data()
        return [row["name"] for row in result_rows]


def get_tenant_provider_databases(tenant_id: UUID, provider_id: UUID) -> list[str]:
    short_tenant_id = get_shortuuid(tenant_id)
    short_provider_id = get_shortuuid(provider_id)
    prefix = TENANT_PROVIDER_DATABASE_NAME_PREFIX_TEMPLATE.format(
        tenant_id=short_tenant_id, provider_id=short_provider_id
    )

    return get_databases_by_prefix(prefix)


def drop_tenant_provider_databases(tenant_id: UUID, provider_id: UUID) -> bool:
    databases = get_tenant_provider_databases(tenant_id, provider_id)
    for database in databases:
        drop_database(database)


def get_tenant_databases(tenant_id: UUID) -> list[str]:
    short_tenant_id = get_shortuuid(tenant_id)
    prefix = TENANT_DATABASE_NAME_PREFIX_TEMPLATE.format(tenant_id=short_tenant_id)

    return get_databases_by_prefix(prefix)


def drop_tenant_databases(tenant_id: UUID) -> None:
    databases = get_tenant_databases(tenant_id)
    for database in databases:
        drop_database(database)


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
