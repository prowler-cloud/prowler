import logging
import os
import tempfile
import threading

from contextlib import contextmanager
from itertools import islice
from typing import Any, Iterator

import neo4j
import neo4j.exceptions

from cartography.intel import create_indexes as cartography_create_indexes
from django.conf import settings

from api.attack_paths.retryable_session import RetryableSession
from tasks.jobs.attack_paths import prowler as attack_paths_prowler

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
def get_session(database: str | None = None) -> Iterator[RetryableSession]:
    session_wrapper: RetryableSession | None = None

    try:
        session_wrapper = RetryableSession(
            session_factory=lambda: get_driver().session(database=database),
            close_driver=close_driver,  # Just to avoid circular imports
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


def drop_subgraph(database: str, root_node_label: str, root_node_id: str, provider_id: str) -> int:
    query = """
        MATCH (rn:__ROOT_NODE_LABEL__ {id: $root_node_id, prowler_provider_id: $prowler_provider_id})
        CALL apoc.path.subgraphNodes(rn, {})
        YIELD node
        DETACH DELETE node
        RETURN COUNT(node) AS deleted_nodes_count
    """.replace("__ROOT_NODE_LABEL__", root_node_label)
    parameters = {
        "root_node_id": root_node_id,
        "prowler_provider_id": provider_id,
    }

    with get_session(database) as session:
        result = session.run(query, parameters)

        try:
            return result.single()["deleted_nodes_count"]

        except neo4j.exceptions.ResultConsumedError:
            return 0  # As there are no nodes to delete, the result is empty


def create_database_dump(database: str, root_node_label: str, root_node_id: str) -> str:
    file_descriptor, dump_filename_path = tempfile.mkstemp(suffix=".neo4jdump")
    os.close(file_descriptor)

    query = """
        CALL {
            MATCH (rn:__ROOT_NODE_LABEL__ {id: $root_node_id})
            CALL apoc.path.subgraphAll(rn, {}) YIELD nodes, relationships
            RETURN nodes, relationships
        }
        WITH nodes, relationships

        CALL {
            // Chunk nodes
            WITH nodes
            UNWIND range(0, size(nodes) - 1, 5000) AS offset
            UNWIND nodes[offset..offset + 5000] AS n
            RETURN apoc.convert.toJson({
                    type:'node',
                    id:id(n),
                    labels:labels(n),
                    properties:properties(n)
            }) AS line

            UNION ALL

            // Chunk relationships
            WITH relationships
            UNWIND range(0, size(relationships) - 1, 5000) AS offset
            UNWIND relationships[offset..offset + 5000] AS r
            RETURN apoc.convert.toJson({
                type:'relationship',
                id:id(r),
                label:type(r),
                start:id(startNode(r)),
                end:id(endNode(r)),
                properties:properties(r)
            }) AS line
        }
        RETURN line
    """.replace("__ROOT_NODE_LABEL__", root_node_label)
    parameters = {"root_node_id": root_node_id}

    with get_session(database) as neo4j_session:
        with open(dump_filename_path, "w", encoding="utf-8") as f:
            for record in neo4j_session.run(query, parameters):
                f.write(record["line"])
                f.write("\n")

    return dump_filename_path


def load_database_dump(dump_filename_path: str, database: str, provider_id: str) -> None:
    BATCH_SIZE = 1000

    query = """
        // Read the batch
        WITH [line IN $lines | apoc.convert.fromJsonMap(line)] AS rows

        // Create nodes from the batch
        CALL {
            WITH rows
            UNWIND rows AS row
            WITH row
            WHERE row.type = 'node'
            MERGE (n {piid: row.id, prowler_provider_id: $prowler_provider_id})
            SET n += COALESCE(row.properties, {})
            SET n:$(COALESCE(row.labels, []))
        }

        // Create relationships from the batch
        CALL {
            WITH rows
            UNWIND rows AS row
            WITH row
            WHERE row.type = 'relationship' AND row.label IS NOT NULL
            MATCH (s {piid: row.start, prowler_provider_id: $prowler_provider_id}),
                (t {piid: row.end, prowler_provider_id: $prowler_provider_id})
            CALL apoc.merge.relationship(
                s,
                row.label,
                {},
                COALESCE(row.properties, {}),
                t
            ) YIELD rel
            RETURN TRUE AS relationship_created
        }
        RETURN relationship_created AS export_finished;

        // It needs to return something because of the use of `apoc.merge.relationship` inside a CALL
    """

    def chunks(iterable, size):
        it = iter(iterable)
        while True:
            batch = list(islice(it, size))
            if not batch:
                break
            yield batch

    with get_session(database) as neo4j_session:
        with open(dump_filename_path, "r", encoding="utf-8") as f:
            for batch in chunks(f, BATCH_SIZE):
                neo4j_session.run(
                    query,
                    {
                        "prowler_provider_id": provider_id,
                        "lines": batch,
                    }
                ).consume()

        cartography_create_indexes.run(neo4j_session, None)
        attack_paths_prowler.create_indexes(neo4j_session)

    os.remove(dump_filename_path)


# Neo4j functions related to Prowler + Cartography
DATABASE_NAME_TEMPLATE = "db-{reference_id}"  # For tenants' main databases, so it uses `tenant_id`
TEMPORAL_DATABASE_NAME_TEMPLATE = "db-tmp-{reference_id}"  # For temporal databases, so it uses `attack_paths_scan_id`


def get_database_name(reference_id: Any, temporal: bool = False) -> str:
    lower_reference_id = str(reference_id).lower()
    template = TEMPORAL_DATABASE_NAME_TEMPLATE if temporal else DATABASE_NAME_TEMPLATE
    return template.format(reference_id=lower_reference_id)


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
