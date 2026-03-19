"""
Graph sync operations for Attack Paths.

This module handles syncing graph data from temporary scan databases
to the tenant database, adding provider isolation labels and properties.
"""

from collections import defaultdict
from typing import Any

import neo4j
from celery.utils.log import get_task_logger

from api.attack_paths import database as graph_database
from tasks.jobs.attack_paths.config import (
    PROVIDER_ISOLATION_PROPERTIES,
    PROVIDER_RESOURCE_LABEL,
    SYNC_BATCH_SIZE,
    get_provider_label,
    get_tenant_label,
)
from tasks.jobs.attack_paths.indexes import IndexType, create_indexes
from tasks.jobs.attack_paths.queries import (
    NODE_FETCH_QUERY,
    NODE_SYNC_TEMPLATE,
    RELATIONSHIP_SYNC_TEMPLATE,
    RELATIONSHIPS_FETCH_QUERY,
    render_cypher_template,
)

logger = get_task_logger(__name__)


def create_sync_indexes(neo4j_session) -> None:
    """Create indexes for provider resource sync operations."""
    create_indexes(neo4j_session, IndexType.SYNC)


def sync_graph(
    source_database: str,
    target_database: str,
    tenant_id: str,
    provider_id: str,
) -> dict[str, int]:
    """
    Sync all nodes and relationships from source to target database.

    Args:
        `source_database`: The temporary scan database
        `target_database`: The tenant database
        `tenant_id`: The tenant ID for isolation
        `provider_id`: The provider ID for isolation

    Returns:
        Dict with counts of synced nodes and relationships
    """
    nodes_synced = sync_nodes(
        source_database,
        target_database,
        tenant_id,
        provider_id,
    )
    relationships_synced = sync_relationships(
        source_database,
        target_database,
        provider_id,
    )

    return {
        "nodes": nodes_synced,
        "relationships": relationships_synced,
    }


def sync_nodes(
    source_database: str,
    target_database: str,
    tenant_id: str,
    provider_id: str,
) -> int:
    """
    Sync nodes from source to target database.

    Adds `_ProviderResource` label and `_provider_id` property to all nodes.
    Also adds dynamic `_Tenant_{id}` and `_Provider_{id}` isolation labels.

    Source and target sessions are opened sequentially per batch to avoid
    holding two Bolt connections simultaneously for the entire sync duration.
    """
    last_id = -1
    total_synced = 0

    while True:
        grouped: dict[tuple[str, ...], list[dict[str, Any]]] = defaultdict(list)
        batch_count = 0

        with graph_database.get_session(source_database) as source_session:
            result = source_session.run(
                NODE_FETCH_QUERY,
                {"last_id": last_id, "batch_size": SYNC_BATCH_SIZE},
            )
            for record in result:
                batch_count += 1
                last_id = record["internal_id"]
                key, value = _node_to_sync_dict(record, provider_id)
                grouped[key].append(value)

        if batch_count == 0:
            break

        with graph_database.get_session(target_database) as target_session:
            for labels, batch in grouped.items():
                label_set = set(labels)
                label_set.add(PROVIDER_RESOURCE_LABEL)
                label_set.add(get_tenant_label(tenant_id))
                label_set.add(get_provider_label(provider_id))
                node_labels = ":".join(f"`{label}`" for label in sorted(label_set))

                query = render_cypher_template(
                    NODE_SYNC_TEMPLATE, {"__NODE_LABELS__": node_labels}
                )
                target_session.run(
                    query,
                    {
                        "rows": batch,
                        "provider_id": provider_id,
                    },
                )

        total_synced += batch_count
        logger.info(
            f"Synced {total_synced} nodes from {source_database} to {target_database}"
        )

    return total_synced


def sync_relationships(
    source_database: str,
    target_database: str,
    provider_id: str,
) -> int:
    """
    Sync relationships from source to target database.

    Adds `_provider_id` property to all relationships.

    Source and target sessions are opened sequentially per batch to avoid
    holding two Bolt connections simultaneously for the entire sync duration.
    """
    last_id = -1
    total_synced = 0

    while True:
        grouped: dict[str, list[dict[str, Any]]] = defaultdict(list)
        batch_count = 0

        with graph_database.get_session(source_database) as source_session:
            result = source_session.run(
                RELATIONSHIPS_FETCH_QUERY,
                {"last_id": last_id, "batch_size": SYNC_BATCH_SIZE},
            )
            for record in result:
                batch_count += 1
                last_id = record["internal_id"]
                key, value = _rel_to_sync_dict(record, provider_id)
                grouped[key].append(value)

        if batch_count == 0:
            break

        with graph_database.get_session(target_database) as target_session:
            for rel_type, batch in grouped.items():
                query = render_cypher_template(
                    RELATIONSHIP_SYNC_TEMPLATE, {"__REL_TYPE__": rel_type}
                )
                target_session.run(
                    query,
                    {
                        "rows": batch,
                        "provider_id": provider_id,
                    },
                )

        total_synced += batch_count
        logger.info(
            f"Synced {total_synced} relationships from {source_database} to {target_database}"
        )

    return total_synced


def _node_to_sync_dict(
    record: neo4j.Record, provider_id: str
) -> tuple[tuple[str, ...], dict[str, Any]]:
    """Transform a source node record into a (grouping_key, sync_dict) pair."""
    props = dict(record["props"] or {})
    _strip_internal_properties(props)
    labels = tuple(sorted(set(record["labels"] or [])))
    return labels, {
        "provider_element_id": f"{provider_id}:{record['element_id']}",
        "props": props,
    }


def _rel_to_sync_dict(
    record: neo4j.Record, provider_id: str
) -> tuple[str, dict[str, Any]]:
    """Transform a source relationship record into a (grouping_key, sync_dict) pair."""
    props = dict(record["props"] or {})
    _strip_internal_properties(props)
    rel_type = record["rel_type"]
    return rel_type, {
        "start_element_id": f"{provider_id}:{record['start_element_id']}",
        "end_element_id": f"{provider_id}:{record['end_element_id']}",
        "provider_element_id": f"{provider_id}:{rel_type}:{record['internal_id']}",
        "props": props,
    }


def _strip_internal_properties(props: dict[str, Any]) -> None:
    """Remove provider isolation properties before the += spread in sync templates."""
    for key in PROVIDER_ISOLATION_PROPERTIES:
        props.pop(key, None)
