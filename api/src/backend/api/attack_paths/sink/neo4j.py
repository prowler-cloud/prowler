"""Neo4j sink implementation.

Owns a Neo4j driver independent from the staging driver. On OSS and local dev
this is the only sink; on hosted deployments it runs only as a legacy read
path while phase-1 drains tenant DBs.
"""

import atexit
import logging
import threading

from contextlib import AbstractContextManager, contextmanager
from typing import Any, Iterator

import neo4j
import neo4j.exceptions

from django.conf import settings

from api.attack_paths.retryable_session import RetryableSession
from api.attack_paths.sink.base import SinkDatabase
from config.env import env

logging.getLogger("neo4j").setLevel(logging.ERROR)
logging.getLogger("neo4j").propagate = False

logger = logging.getLogger(__name__)

SERVICE_UNAVAILABLE_MAX_RETRIES = env.int(
    "ATTACK_PATHS_SERVICE_UNAVAILABLE_MAX_RETRIES", default=3
)
READ_QUERY_TIMEOUT_SECONDS = env.int(
    "ATTACK_PATHS_READ_QUERY_TIMEOUT_SECONDS", default=30
)
CONN_ACQUISITION_TIMEOUT = env.int("NEO4J_CONN_ACQUISITION_TIMEOUT", default=15)
MAX_CONNECTION_LIFETIME = env.int("NEO4J_MAX_CONNECTION_LIFETIME", default=7200)
MAX_CONNECTION_POOL_SIZE = env.int("NEO4J_MAX_CONNECTION_POOL_SIZE", default=50)

READ_EXCEPTION_CODES = [
    "Neo.ClientError.Statement.AccessMode",
    "Neo.ClientError.Procedure.ProcedureNotFound",
]
CLIENT_STATEMENT_EXCEPTION_PREFIX = "Neo.ClientError.Statement."
DATABASE_NOT_FOUND_CODE = "Neo.ClientError.Database.DatabaseNotFound"


class Neo4jSink(SinkDatabase):
    """Neo4j-backed sink. Multi-database cluster; tenant isolation is physical."""

    def __init__(self) -> None:
        self._driver: neo4j.Driver | None = None
        self._lock = threading.Lock()
        self._atexit_registered = False

    # Driver

    def _config(self) -> dict:
        return settings.DATABASES["neo4j"]

    def _uri(self) -> str:
        cfg = self._config()
        host = cfg["HOST"]
        port = cfg["PORT"]
        if not host or not port:
            raise RuntimeError(
                "NEO4J_HOST / NEO4J_PORT must be set when ATTACK_PATHS_SINK_DATABASE=neo4j"
            )
        return f"bolt://{host}:{port}"

    def init(self) -> neo4j.Driver:
        if self._driver is not None:
            return self._driver
        with self._lock:
            if self._driver is None:
                cfg = self._config()
                self._driver = neo4j.GraphDatabase.driver(
                    self._uri(),
                    auth=(cfg["USER"], cfg["PASSWORD"]),
                    keep_alive=True,
                    max_connection_lifetime=MAX_CONNECTION_LIFETIME,
                    connection_acquisition_timeout=CONN_ACQUISITION_TIMEOUT,
                    max_connection_pool_size=MAX_CONNECTION_POOL_SIZE,
                )
                # Eager connectivity check is best-effort:
                # A Neo4 that is down at boot must not crash the process, same degradation model as Postgres
                # The driver reconnects lazily on first use
                # /health/ready surfaces the outage until it recovers
                try:
                    self._driver.verify_connectivity()

                except Exception:
                    logger.warning(
                        "Neo4j sink unreachable at init; continuing with a lazily-reconnecting driver",
                        exc_info=True,
                    )

                if not self._atexit_registered:
                    atexit.register(self.close)
                    self._atexit_registered = True
        return self._driver

    def _get_driver(self) -> neo4j.Driver:
        return self.init()

    def verify_connectivity(self) -> None:
        self._get_driver().verify_connectivity()

    def close(self) -> None:
        with self._lock:
            if self._driver is not None:
                try:
                    self._driver.close()
                finally:
                    self._driver = None

    # Sessions

    @contextmanager
    def get_session(
        self,
        database: str | None = None,
        default_access_mode: str | None = None,
    ) -> Iterator[RetryableSession]:
        from api.attack_paths.database import (
            ClientStatementException,
            GraphDatabaseQueryException,
            WriteQueryNotAllowedException,
        )

        session_wrapper: RetryableSession | None = None
        try:
            session_wrapper = RetryableSession(
                session_factory=lambda: self._get_driver().session(
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

    # Operations

    def execute_read_query(
        self,
        database: str,
        cypher: str,
        parameters: dict[str, Any] | None = None,
    ) -> neo4j.graph.Graph:
        with self.get_session(
            database, default_access_mode=neo4j.READ_ACCESS
        ) as session:

            def _run(tx: neo4j.ManagedTransaction) -> neo4j.graph.Graph:
                result = tx.run(
                    cypher, parameters or {}, timeout=READ_QUERY_TIMEOUT_SECONDS
                )
                return result.graph()

            return session.execute_read(_run)

    def create_database(self, database: str) -> None:
        with self.get_session() as session:
            session.run(
                "CREATE DATABASE $database IF NOT EXISTS", {"database": database}
            )

    def drop_database(self, database: str) -> None:
        with self.get_session() as session:
            session.run(f"DROP DATABASE `{database}` IF EXISTS DESTROY DATA")

    def drop_subgraph(self, database: str, provider_id: str) -> int:
        """Delete all nodes for a provider from a tenant database, batched."""
        from api.attack_paths.database import GraphDatabaseQueryException
        from tasks.jobs.attack_paths.config import (
            BATCH_SIZE,
            PROVIDER_RESOURCE_LABEL,
            get_provider_label,
        )

        provider_label = get_provider_label(provider_id)
        deleted_nodes = 0

        try:
            with self.get_session(database) as session:
                deleted_count = 1
                while deleted_count > 0:
                    result = session.run(
                        f"""
                        MATCH (n:{PROVIDER_RESOURCE_LABEL}:`{provider_label}`)
                        WITH n LIMIT $batch_size
                        DETACH DELETE n
                        RETURN COUNT(n) AS deleted_nodes_count
                        """,
                        {"batch_size": BATCH_SIZE},
                    )
                    deleted_count = result.single().get("deleted_nodes_count", 0)
                    deleted_nodes += deleted_count

        except GraphDatabaseQueryException as exc:
            if exc.code == DATABASE_NOT_FOUND_CODE:
                return 0
            raise

        return deleted_nodes

    def has_provider_data(self, database: str, provider_id: str) -> bool:
        from api.attack_paths.database import GraphDatabaseQueryException
        from tasks.jobs.attack_paths.config import (
            PROVIDER_RESOURCE_LABEL,
            get_provider_label,
        )

        provider_label = get_provider_label(provider_id)
        query = (
            f"MATCH (n:{PROVIDER_RESOURCE_LABEL}:`{provider_label}`) RETURN 1 LIMIT 1"
        )
        try:
            with self.get_session(
                database, default_access_mode=neo4j.READ_ACCESS
            ) as session:
                result = session.run(query)
                return result.single() is not None

        except GraphDatabaseQueryException as exc:
            if exc.code == DATABASE_NOT_FOUND_CODE:
                return False
            raise

    def clear_cache(self, database: str) -> None:
        from api.attack_paths.database import GraphDatabaseQueryException

        try:
            with self.get_session(database) as session:
                session.run("CALL db.clearQueryCaches()")
        except GraphDatabaseQueryException as exc:
            logging.warning(
                f"Failed to clear query cache for database `{database}`: {exc}"
            )

    # Sync write path

    def ensure_sync_indexes(self, database: str) -> None:
        """Create the `_provider_element_id` lookup index on `_ProviderResource`.

        Every synced node carries the `_ProviderResource` label, so a single
        index covers both node-upserts and relationship endpoint MATCHes.
        Without this index the rel sync degrades to a label scan per row and
        large provider syncs become unworkable.
        """
        from tasks.jobs.attack_paths.config import (
            PROVIDER_ELEMENT_ID_PROPERTY,
            PROVIDER_RESOURCE_LABEL,
        )

        query = (
            f"CREATE INDEX provider_element_id_idx IF NOT EXISTS "
            f"FOR (n:`{PROVIDER_RESOURCE_LABEL}`) "
            f"ON (n.`{PROVIDER_ELEMENT_ID_PROPERTY}`)"
        )
        with self.get_session(database) as session:
            session.run(query).consume()

    def write_nodes(
        self,
        database: str,
        labels: str,
        rows: list[dict[str, Any]],
    ) -> None:
        if not rows:
            return
        from tasks.jobs.attack_paths.config import (
            PROVIDER_ELEMENT_ID_PROPERTY,
            PROVIDER_RESOURCE_LABEL,
        )

        query = f"""
            UNWIND $rows AS row
            MERGE (n:`{PROVIDER_RESOURCE_LABEL}` {{`{PROVIDER_ELEMENT_ID_PROPERTY}`: row.provider_element_id}})
            SET n:{labels}
            SET n += row.props
        """
        with self.get_session(database) as session:
            session.run(query, {"rows": rows}).consume()

    def write_relationships(
        self,
        database: str,
        rel_type: str,
        provider_id: str,
        rows: list[dict[str, Any]],
    ) -> None:
        if not rows:
            return
        from tasks.jobs.attack_paths.config import (
            PROVIDER_ELEMENT_ID_PROPERTY,
            PROVIDER_RESOURCE_LABEL,
            get_provider_label,
        )

        provider_label = get_provider_label(provider_id)
        query = f"""
            UNWIND $rows AS row
            MATCH (s:`{PROVIDER_RESOURCE_LABEL}`:`{provider_label}` {{`{PROVIDER_ELEMENT_ID_PROPERTY}`: row.start_element_id}})
            MATCH (t:`{PROVIDER_RESOURCE_LABEL}`:`{provider_label}` {{`{PROVIDER_ELEMENT_ID_PROPERTY}`: row.end_element_id}})
            MERGE (s)-[r:`{rel_type}` {{`{PROVIDER_ELEMENT_ID_PROPERTY}`: row.provider_element_id}}]->(t)
            SET r += row.props
        """
        with self.get_session(database) as session:
            session.run(query, {"rows": rows}).consume()

    # For compatibility with test harnesses that patch the concrete driver
    def get_driver(self) -> neo4j.Driver:
        return self._get_driver()


# Helper for tests / external callers that want a writer session specifically
def get_read_session(
    sink: Neo4jSink, database: str
) -> AbstractContextManager[RetryableSession]:
    return sink.get_session(database, default_access_mode=neo4j.READ_ACCESS)
