"""Shared batched deletion helpers for sink backends."""

import logging
import time
from typing import Any

RELATIONSHIP_DELETE_QUERY_TEMPLATES = {
    "outgoing relationship": """
        MATCH (n:`{provider_label}`)-[r]->()
        WITH r LIMIT $batch_size
        DELETE r
        RETURN COUNT(r) AS deleted_rels_count
        """,
    "incoming relationship": """
        MATCH (n:`{provider_label}`)<-[r]-()
        WITH r LIMIT $batch_size
        DELETE r
        RETURN COUNT(r) AS deleted_rels_count
        """,
}

NODE_DELETE_QUERY_TEMPLATE = """
    MATCH (n:{provider_resource_label}:`{provider_label}`)
    WITH n LIMIT $batch_size
    DELETE n
    RETURN COUNT(n) AS deleted_nodes_count
    """


def delete_batches(
    *,
    session: Any,
    logger: logging.Logger,
    log_target: str,
    provider_id: str,
    query: str,
    phase: str,
    count_key: str,
    total_key: str,
    deleted_key: str,
    initial_total: int,
    batch_size: int,
    drop_t0: float,
) -> tuple[int, int]:
    deleted_total = initial_total
    batches = 0
    while True:
        logger.info(
            "Deleting %s batch from %s "
            "(provider=%s, batch=%s, total_%s=%s, elapsed=%.3fs)",
            phase,
            log_target,
            provider_id,
            batches + 1,
            total_key,
            deleted_total,
            time.perf_counter() - drop_t0,
        )
        record = session.run(query, {"batch_size": batch_size}).single()
        deleted = (record[count_key] if record else 0) or 0
        if deleted == 0:
            return deleted_total, batches

        batches += 1
        deleted_total += deleted
        logger.info(
            "Deleted %s batch from %s "
            "(provider=%s, batch=%s, %s=%s, total_%s=%s, elapsed=%.3fs)",
            phase,
            log_target,
            provider_id,
            batches,
            deleted_key,
            deleted,
            total_key,
            deleted_total,
            time.perf_counter() - drop_t0,
        )
