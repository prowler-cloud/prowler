"""AWS Neptune sink implementation.

Dual Bolt drivers: one against the writer endpoint for workers, one against
the reader endpoint for the API read path. If `NEPTUNE_READER_ENDPOINT` is
unset the reader falls back to the writer driver so single-node clusters work.

Neptune is single-database. The `database` argument on the SinkDatabase
protocol is ignored; tenant / provider isolation is enforced by labels that
the sync step already writes on every node (see tasks/jobs/attack_paths/sync.py).

SigV4 auth lives at the bottom of this file as `neptune_auth_provider`. The
neo4j driver invokes the returned callable on each token refresh.
"""

import atexit
import datetime
import json
import logging
import threading

from contextlib import contextmanager
from typing import Any, Callable, Iterator
from urllib.parse import urlsplit

import neo4j
import neo4j.exceptions

from botocore.auth import SigV4Auth
from botocore.awsrequest import AWSRequest
from botocore.session import Session as BotoSession
from django.conf import settings
from neo4j.auth_management import AuthManagers, ExpiringAuth

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
# Neptune serverless cold-start can be >30s; give the driver room
CONN_ACQUISITION_TIMEOUT = env.int("NEPTUNE_CONN_ACQUISITION_TIMEOUT", default=60)
# Roll connections hourly so SigV4 rotations and cert refreshes don't strand long-lived pool entries
MAX_CONNECTION_LIFETIME = env.int("NEPTUNE_MAX_CONNECTION_LIFETIME", default=3600)
MAX_CONNECTION_POOL_SIZE = env.int("NEPTUNE_MAX_CONNECTION_POOL_SIZE", default=50)

READ_EXCEPTION_CODES = [
    "Neo.ClientError.Statement.AccessMode",
    "Neo.ClientError.Procedure.ProcedureNotFound",
]
CLIENT_STATEMENT_EXCEPTION_PREFIX = "Neo.ClientError.Statement."

# Refresh 60s before the 5-minute SigV4 window closes
SIGV4_TOKEN_LIFETIME_MINUTES = 4


class NeptuneSink(SinkDatabase):
    """Neptune-backed sink. Single database; isolation is label-based."""

    def __init__(self) -> None:
        self._writer: neo4j.Driver | None = None
        self._reader: neo4j.Driver | None = None
        self._lock = threading.Lock()
        self._atexit_registered = False

    # Config

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
            auth=AuthManagers.bearer(
                neptune_auth_provider(region, self._https_url(endpoint, port))
            ),
            keep_alive=True,
            max_connection_lifetime=MAX_CONNECTION_LIFETIME,
            connection_acquisition_timeout=CONN_ACQUISITION_TIMEOUT,
            max_connection_pool_size=MAX_CONNECTION_POOL_SIZE,
            max_transaction_retry_time=0,
        )

    # Lifecycle

    def init(self) -> None:
        if self._writer is not None:
            return
        with self._lock:
            if self._writer is None:
                cfg = self._config()
                writer_endpoint = cfg["WRITER_ENDPOINT"]
                reader_endpoint = cfg["READER_ENDPOINT"] or writer_endpoint

                # Eager connectivity checks are best-effort
                # A Neptune that is down at boot must not crash the process, same degradation model as Postgres
                # Drivers reconnect lazily on first use
                # /health/ready surfaces the outage until it recovers
                self._writer = self._build_driver(writer_endpoint)
                self._verify_best_effort(self._writer, "writer")

                if reader_endpoint == writer_endpoint:
                    self._reader = self._writer

                else:
                    self._reader = self._build_driver(reader_endpoint)
                    self._verify_best_effort(self._reader, "reader")

                if not self._atexit_registered:
                    atexit.register(self.close)
                    self._atexit_registered = True

    def close(self) -> None:
        with self._lock:
            # `Driver.close()` is idempotent, so closing the same driver twice
            # (when reader aliases writer on single-endpoint configs) is safe
            for driver in (self._reader, self._writer):
                if driver is None:
                    continue
                try:
                    driver.close()
                except Exception:  # pragma: no cover - best-effort
                    pass
            self._writer = None
            self._reader = None

    # Sessions

    def _get_writer(self) -> neo4j.Driver:
        self.init()
        assert self._writer is not None
        return self._writer

    def _get_reader(self) -> neo4j.Driver:
        self.init()
        assert self._reader is not None
        return self._reader

    @staticmethod
    def _verify_best_effort(driver: neo4j.Driver, role: str) -> None:
        try:
            driver.verify_connectivity()

        except Exception:
            logger.warning(
                "Neptune %s endpoint unreachable at init; continuing with a lazily-reconnecting driver",
                role,
                exc_info=True,
            )

    def verify_connectivity(self) -> None:
        # The API read path uses the reader driver
        # On single-endpoint clusters it aliases the writer, so this also covers the writer
        # A writer-only outage is a workers' concern (no HTTP probe there) and deliberately does not fail API readiness
        self._get_reader().verify_connectivity()

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

    # Operations

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
        """Delete a provider's subgraph in two bounded phases.

        Neptune write transactions are capped at ~2 minutes. A naive
        `DETACH DELETE` on a label-scanned batch grows unbounded with graph
        density (one node can drag thousands of relationships into the same
        transaction). Instead:

        1. Delete relationships incident to provider nodes, one fixed-size
           batch per transaction.
        2. Delete the now-orphaned nodes, one fixed-size batch per transaction.

        Each transaction does work proportional to `batch_size`, never to the
        graph's branching factor.
        """
        from tasks.jobs.attack_paths.config import (
            BATCH_SIZE,
            PROVIDER_RESOURCE_LABEL,
            get_provider_label,
        )

        provider_label = get_provider_label(provider_id)

        with self.get_session() as session:
            while True:
                result = session.run(
                    f"""
                    MATCH (:`{provider_label}`)-[r]-()
                    WITH r LIMIT $batch_size
                    DELETE r
                    RETURN COUNT(r) AS deleted_rels_count
                    """,
                    {"batch_size": BATCH_SIZE},
                )
                record = result.single()
                deleted_rels = (record["deleted_rels_count"] if record else 0) or 0
                if deleted_rels == 0:
                    break

            deleted_nodes = 0
            while True:
                result = session.run(
                    f"""
                    MATCH (n:`{PROVIDER_RESOURCE_LABEL}`:`{provider_label}`)
                    WITH n LIMIT $batch_size
                    DELETE n
                    RETURN COUNT(n) AS deleted_nodes_count
                    """,
                    {"batch_size": BATCH_SIZE},
                )
                record = result.single()
                deleted = (record["deleted_nodes_count"] if record else 0) or 0
                if deleted == 0:
                    break
                deleted_nodes += deleted

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

    # Sync write path

    def ensure_sync_indexes(self, database: str) -> None:  # noqa: ARG002
        # Neptune routes node and relationship lookups through `~id`, which is the cluster's primary key
        # No additional index is needed or supported
        return None

    def write_nodes(
        self,
        database: str,  # noqa: ARG002
        labels: str,
        rows: list[dict[str, Any]],
    ) -> None:
        if not rows:
            return
        from tasks.jobs.attack_paths.config import (
            PROVIDER_ELEMENT_ID_PROPERTY,
            PROVIDER_RESOURCE_LABEL,
        )

        # MERGE on `~id` is the documented and engine-optimized idempotent
        # upsert pattern for Neptune openCypher. The label inside the MERGE
        # matters: Neptune assigns a default `vertex` label to any node
        # created without an explicit one, so we pin `_ProviderResource`
        # (which every synced node carries anyway) at MERGE-time. Additional
        # labels are added after
        #
        # We also write `_provider_element_id` as a regular property so
        # non-sync code (drop_subgraph, query helpers) keeps a stable contract
        # that doesn't know about `~id`
        query = f"""
            UNWIND $rows AS row
            MERGE (n:`{PROVIDER_RESOURCE_LABEL}` {{`~id`: row.provider_element_id}})
            SET n:{labels}
            SET n += row.props
            SET n.`{PROVIDER_ELEMENT_ID_PROPERTY}` = row.provider_element_id
        """
        with self.get_session() as session:
            session.run(query, {"rows": rows}).consume()

    def write_relationships(
        self,
        database: str,  # noqa: ARG002
        rel_type: str,
        provider_id: str,  # noqa: ARG002 - encoded in start/end `~id` already
        rows: list[dict[str, Any]],
    ) -> None:
        if not rows:
            return
        from tasks.jobs.attack_paths.config import PROVIDER_ELEMENT_ID_PROPERTY

        # `id(n) = $value` is Neptune's parameterized fast path; both endpoint
        # MATCHes resolve in O(1) via the system `~id`, so per-row work stays
        # bounded regardless of batch size
        query = f"""
            UNWIND $rows AS row
            MATCH (s) WHERE id(s) = row.start_element_id
            MATCH (e) WHERE id(e) = row.end_element_id
            MERGE (s)-[r:`{rel_type}` {{`{PROVIDER_ELEMENT_ID_PROPERTY}`: row.provider_element_id}}]->(e)
            SET r += row.props
        """
        with self.get_session() as session:
            session.run(query, {"rows": rows}).consume()

    # Test helpers

    def get_writer(self) -> neo4j.Driver:
        return self._get_writer()

    def get_reader(self) -> neo4j.Driver:
        return self._get_reader()


# SigV4 auth provider


class _NeptuneAuthToken(neo4j.Auth):
    """Neo4j Auth backed by a SigV4-signed GET to `/opencypher`."""

    def __init__(self, region: str, url: str) -> None:
        session = BotoSession()
        credentials = session.get_credentials()
        if credentials is None:
            raise RuntimeError(
                "No AWS credentials available for Neptune SigV4 signing. "
                "Ensure the boto3 credential chain can resolve."
            )
        credentials = credentials.get_frozen_credentials()

        request = AWSRequest(method="GET", url=url + "/opencypher")
        request.headers.add_header("Host", urlsplit(url).hostname)
        SigV4Auth(credentials, "neptune-db", region).add_auth(request)

        auth_obj = {
            header: request.headers[header]
            for header in (
                "Authorization",
                "X-Amz-Date",
                "X-Amz-Security-Token",
                "Host",
            )
            if header in request.headers
        }
        auth_obj["HttpMethod"] = "GET"

        super().__init__("basic", "username", json.dumps(auth_obj))


def neptune_auth_provider(region: str, https_url: str) -> Callable[[], ExpiringAuth]:
    """Return a callable the neo4j driver can invoke to refresh credentials."""

    def _provider() -> ExpiringAuth:
        token = _NeptuneAuthToken(region, https_url)
        expires_at = (
            datetime.datetime.now(datetime.timezone.utc)
            + datetime.timedelta(minutes=SIGV4_TOKEN_LIFETIME_MINUTES)
        ).timestamp()
        return ExpiringAuth(auth=token, expires_at=expires_at)

    return _provider
