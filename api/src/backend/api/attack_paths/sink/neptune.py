"""AWS Neptune sink implementation.

Dual Bolt drivers: one against the writer endpoint for workers, one against
the reader endpoint for the API read path. If ``NEPTUNE_READER_ENDPOINT`` is
unset the reader falls back to the writer driver so single-node clusters work.

Neptune is single-database. The ``database`` argument on the SinkDatabase
protocol is ignored; tenant / provider isolation is enforced by labels that
the sync step already writes on every node (see tasks/jobs/attack_paths/sync.py).
"""
from __future__ import annotations

import atexit
import logging
import threading
from contextlib import AbstractContextManager, contextmanager
from typing import Any, Iterator

import neo4j
import neo4j.exceptions
from config.env import env
from django.conf import settings

from api.attack_paths.retryable_session import RetryableSession
from api.attack_paths.sink.auth_neptune import neptune_auth_provider
from api.attack_paths.sink.base import SinkDatabase

logging.getLogger("neo4j").setLevel(logging.ERROR)
logging.getLogger("neo4j").propagate = False

SERVICE_UNAVAILABLE_MAX_RETRIES = env.int(
    "ATTACK_PATHS_SERVICE_UNAVAILABLE_MAX_RETRIES", default=3
)
READ_QUERY_TIMEOUT_SECONDS = env.int(
    "ATTACK_PATHS_READ_QUERY_TIMEOUT_SECONDS", default=30
)
# Neptune serverless cold-start can be >30s; give the driver room.
CONN_ACQUISITION_TIMEOUT = env.int("NEPTUNE_CONN_ACQUISITION_TIMEOUT", default=60)
# Roll connections hourly so SigV4 rotations and cert refreshes don't strand
# long-lived pool entries.
MAX_CONNECTION_LIFETIME = env.int("NEPTUNE_MAX_CONNECTION_LIFETIME", default=3600)
MAX_CONNECTION_POOL_SIZE = env.int("NEPTUNE_MAX_CONNECTION_POOL_SIZE", default=50)

READ_EXCEPTION_CODES = [
    "Neo.ClientError.Statement.AccessMode",
    "Neo.ClientError.Procedure.ProcedureNotFound",
]
CLIENT_STATEMENT_EXCEPTION_PREFIX = "Neo.ClientError.Statement."


class NeptuneSink(SinkDatabase):
    """Neptune-backed sink. Single database; isolation is label-based."""

    def __init__(self) -> None:
        self._writer: neo4j.Driver | None = None
        self._reader: neo4j.Driver | None = None
        self._lock = threading.Lock()
        self._atexit_registered = False

    # ------------------------------------------------------------------ config

    def _config(self) -> dict:
        return settings.DATABASES["neptune"]

    def _bolt_uri(self, endpoint: str, port: str) -> str:
        return f"bolt+s://{endpoint}:{port}"

    def _https_url(self, endpoint: str, port: str) -> str:
        return f"https://{endpoint}:{port}"

    def _build_driver(self, endpoint: str) -> neo4j.Driver:
        cfg = self._config()
        port = cfg["PORT"]
        region = cfg["REGION"]
        if not endpoint or not region:
            raise RuntimeError(
                "NEPTUNE_WRITER_ENDPOINT and AWS_REGION must be set when "
                "ATTACK_PATHS_SINK_DATABASE=neptune"
            )
        return neo4j.GraphDatabase.driver(
            self._bolt_uri(endpoint, port),
            auth=neptune_auth_provider(region, self._https_url(endpoint, port)),
            encrypted=True,
            keep_alive=True,
            max_connection_lifetime=MAX_CONNECTION_LIFETIME,
            connection_acquisition_timeout=CONN_ACQUISITION_TIMEOUT,
            max_connection_pool_size=MAX_CONNECTION_POOL_SIZE,
            max_transaction_retry_time=0,
        )

    # ------------------------------------------------------------------ lifecycle

    def init(self) -> None:
        if self._writer is not None:
            return
        with self._lock:
            if self._writer is None:
                cfg = self._config()
                writer_endpoint = cfg["WRITER_ENDPOINT"]
                reader_endpoint = cfg["READER_ENDPOINT"] or writer_endpoint

                self._writer = self._build_driver(writer_endpoint)
                self._writer.verify_connectivity()

                if reader_endpoint == writer_endpoint:
                    self._reader = self._writer
                else:
                    self._reader = self._build_driver(reader_endpoint)
                    self._reader.verify_connectivity()

                if not self._atexit_registered:
                    atexit.register(self.close)
                    self._atexit_registered = True

    def close(self) -> None:
        with self._lock:
            for attr in ("_reader", "_writer"):
                driver = getattr(self, attr)
                if driver is not None and driver is not getattr(self, "_writer", None) or attr == "_writer":
                    # reader may alias writer; close each underlying driver once
                    pass
            # Close in defined order, guarding against reader==writer aliasing
            closed: set[int] = set()
            for driver in (self._reader, self._writer):
                if driver is None or id(driver) in closed:
                    continue
                try:
                    driver.close()
                except Exception:  # pragma: no cover - best-effort
                    pass
                closed.add(id(driver))
            self._writer = None
            self._reader = None

    # ------------------------------------------------------------------ sessions

    def _get_writer(self) -> neo4j.Driver:
        self.init()
        assert self._writer is not None
        return self._writer

    def _get_reader(self) -> neo4j.Driver:
        self.init()
        assert self._reader is not None
        return self._reader

    @contextmanager
    def get_session(
        self,
        database: str | None = None,  # noqa: ARG002 - ignored on Neptune
        default_access_mode: str | None = None,
    ) -> Iterator[RetryableSession]:
        from api.attack_paths.database import (
            ClientStatementException,
            GraphDatabaseQueryException,
            WriteQueryNotAllowedException,
        )

        driver = (
            self._get_reader()
            if default_access_mode == neo4j.READ_ACCESS
            else self._get_writer()
        )

        session_wrapper: RetryableSession | None = None
        try:
            session_wrapper = RetryableSession(
                session_factory=lambda: driver.session(
                    default_access_mode=default_access_mode
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

    # ------------------------------------------------------------------ operations

    def execute_read_query(
        self,
        database: str,  # noqa: ARG002 - ignored on Neptune
        cypher: str,
        parameters: dict[str, Any] | None = None,
    ) -> neo4j.graph.Graph:
        with self.get_session(default_access_mode=neo4j.READ_ACCESS) as session:

            def _run(tx: neo4j.ManagedTransaction) -> neo4j.graph.Graph:
                result = tx.run(
                    cypher, parameters or {}, timeout=READ_QUERY_TIMEOUT_SECONDS
                )
                return result.graph()

            return session.execute_read(_run)

    def create_database(self, database: str) -> None:  # noqa: ARG002
        # Neptune clusters are single-database; there is nothing to create.
        return None

    def drop_database(self, database: str) -> None:  # noqa: ARG002
        # Neptune clusters are single-database; there is nothing to drop.
        return None

    def drop_subgraph(self, database: str, provider_id: str) -> int:  # noqa: ARG002
        from tasks.jobs.attack_paths.config import (
            BATCH_SIZE,
            PROVIDER_RESOURCE_LABEL,
            get_provider_label,
        )

        provider_label = get_provider_label(provider_id)
        deleted_nodes = 0
        with self.get_session() as session:
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
                record = result.single()
                deleted_count = (record or {}).get("deleted_nodes_count", 0) if record else 0
                deleted_nodes += deleted_count

        return deleted_nodes

    def has_provider_data(self, database: str, provider_id: str) -> bool:  # noqa: ARG002
        from tasks.jobs.attack_paths.config import (
            PROVIDER_RESOURCE_LABEL,
            get_provider_label,
        )

        provider_label = get_provider_label(provider_id)
        query = (
            f"MATCH (n:{PROVIDER_RESOURCE_LABEL}:`{provider_label}`) RETURN 1 LIMIT 1"
        )
        with self.get_session(default_access_mode=neo4j.READ_ACCESS) as session:
            result = session.run(query)
            return result.single() is not None

    def clear_cache(self, database: str) -> None:  # noqa: ARG002
        # Neptune has no user-facing cache-clear procedure; no-op.
        return None

    # Test helpers
    def get_writer(self) -> neo4j.Driver:
        return self._get_writer()

    def get_reader(self) -> neo4j.Driver:
        return self._get_reader()
