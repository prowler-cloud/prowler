"""
Graph sync operations for Attack Paths.

This module handles syncing graph data from temporary scan databases
to the tenant database, adding provider isolation labels and properties.
"""

from collections import defaultdict
from typing import Any

from celery.utils.log import get_task_logger

from api.attack_paths import database as graph_database
from tasks.jobs.attack_paths.config import (
    BATCH_SIZE,
    DEPRECATED_PROVIDER_RESOURCE_LABEL,
    PROVIDER_RESOURCE_LABEL,
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
    provider_id: str,
) -> dict[str, int]:
    """
    Sync all nodes and relationships from source to target database.

    Args:
        `source_database`: The temporary scan database
        `target_database`: The tenant database
        `provider_id`: The provider ID for isolation

    Returns:
        Dict with counts of synced nodes and relationships
    """
    nodes_synced = sync_nodes(
        source_database,
        target_database,
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
    provider_id: str,
) -> int:
    """
    Sync nodes from source to target database.

    Adds `_ProviderResource` label and `_provider_id` property to all nodes.
    """
    last_id = -1
    total_synced = 0

    with (
        graph_database.get_session(source_database) as source_session,
        graph_database.get_session(target_database) as target_session,
    ):
        while True:
            rows = list(
                source_session.run(
                    NODE_FETCH_QUERY,
                    {"last_id": last_id, "batch_size": BATCH_SIZE},
                )
            )

            if not rows:
                break

            last_id = rows[-1]["internal_id"]

            grouped: dict[tuple[str, ...], list[dict[str, Any]]] = defaultdict(list)
            for row in rows:
                labels = tuple(sorted(set(row["labels"] or [])))
                props = dict(row["props"] or {})
                _strip_internal_properties(props)
                provider_element_id = f"{provider_id}:{row['element_id']}"
                grouped[labels].append(
                    {
                        "provider_element_id": provider_element_id,
                        "props": props,
                    }
                )

            for labels, batch in grouped.items():
                label_set = set(labels)
                label_set.add(PROVIDER_RESOURCE_LABEL)
                label_set.add(DEPRECATED_PROVIDER_RESOURCE_LABEL)
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

            total_synced += len(rows)
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
    """
    last_id = -1
    total_synced = 0

    with (
        graph_database.get_session(source_database) as source_session,
        graph_database.get_session(target_database) as target_session,
    ):
        while True:
            rows = list(
                source_session.run(
                    RELATIONSHIPS_FETCH_QUERY,
                    {"last_id": last_id, "batch_size": BATCH_SIZE},
                )
            )

            if not rows:
                break

            last_id = rows[-1]["internal_id"]

            grouped: dict[str, list[dict[str, Any]]] = defaultdict(list)
            for row in rows:
                props = dict(row["props"] or {})
                _strip_internal_properties(props)
                rel_type = row["rel_type"]
                grouped[rel_type].append(
                    {
                        "start_element_id": f"{provider_id}:{row['start_element_id']}",
                        "end_element_id": f"{provider_id}:{row['end_element_id']}",
                        "provider_element_id": f"{provider_id}:{rel_type}:{row['internal_id']}",
                        "props": props,
                    }
                )

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

            total_synced += len(rows)
            logger.info(
                f"Synced {total_synced} relationships from {source_database} to {target_database}"
            )

    return total_synced


def _strip_internal_properties(props: dict[str, Any]) -> None:
    """Remove internal properties that shouldn't be copied during sync."""
    for key in [
        "_provider_element_id",
        "_provider_id",
        "provider_element_id",  # Deprecated
        "provider_id",  # Deprecated
    ]:
        props.pop(key, None)
