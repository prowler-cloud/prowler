"""Drain the legacy Neo4j tenant DB after a Neptune-sink scan finishes.

When the sink is Neptune, each successful scan's data lives in Neptune.
Pre-migration scans for the same provider may still live in the Neo4j
tenant DB; those rows are unreachable via the API (``is_neptune=False``
scans go through a Neo4j backend) but the graph data persists in Neo4j
until we explicitly delete it.

This module walks that cleanup: after Neptune write succeeds, delete this
provider's subgraph from the Neo4j tenant DB, and drop the tenant DB if it
becomes empty. All failures are logged and swallowed — the Neptune write
already succeeded, the drain is opportunistic.

# TODO: Drop after Neptune migration is finished
"""
from __future__ import annotations

import logging
from uuid import UUID

from tasks.jobs.attack_paths.config import (
    PROVIDER_RESOURCE_LABEL,
)

from api.attack_paths.database import (
    GraphDatabaseQueryException,
    get_database_name,
)

logger = logging.getLogger(__name__)

DATABASE_NOT_FOUND_CODE = "Neo.ClientError.Database.DatabaseNotFound"


def drain_legacy_neo4j_for_provider(
    tenant_id: str | UUID, provider_id: str | UUID
) -> None:
    """Drop this provider's legacy Neo4j subgraph; drop the tenant DB if empty.

    Builds a Neo4j sink handle directly, independent of the currently active
    sink backend (which is Neptune when this function is invoked). The whole
    body is wrapped in try/except so a failed drain never fails a scan whose
    Neptune write already succeeded.
    """
    try:
        from api.attack_paths.sink.neo4j import Neo4jSink

        tenant_db = get_database_name(tenant_id, temporary=False)
        sink = Neo4jSink()

        if not _has_any_data(sink, tenant_db):
            logger.info(
                f"Legacy Neo4j tenant DB {tenant_db} has no data; nothing to drain"
            )
            _close_silently(sink)
            return

        if sink.has_provider_data(tenant_db, str(provider_id)):
            deleted = sink.drop_subgraph(tenant_db, str(provider_id))
            logger.info(
                f"Drained provider {provider_id} from legacy Neo4j tenant DB {tenant_db} "
                f"(deleted_nodes={deleted})"
            )

        if not _has_any_data(sink, tenant_db):
            logger.info(
                f"Legacy Neo4j tenant DB {tenant_db} is now empty; dropping"
            )
            sink.drop_database(tenant_db)

        _close_silently(sink)

    except Exception as exc:  # pragma: no cover - defensive
        logger.warning(
            f"Legacy Neo4j drain failed for provider {provider_id} in tenant "
            f"{tenant_id} (Neptune write already succeeded): {exc}",
            exc_info=True,
        )


def _has_any_data(sink, database: str) -> bool:
    """True if the tenant DB has any ``_ProviderResource`` node."""
    import neo4j

    try:
        with sink.get_session(database, default_access_mode=neo4j.READ_ACCESS) as session:
            result = session.run(
                f"MATCH (n:{PROVIDER_RESOURCE_LABEL}) RETURN 1 LIMIT 1"
            )
            return result.single() is not None
    except GraphDatabaseQueryException as exc:
        if exc.code == DATABASE_NOT_FOUND_CODE:
            return False
        raise


def _close_silently(sink) -> None:
    try:
        sink.close()
    except Exception:  # pragma: no cover
        pass
