"""
Graph sync operations for Attack Paths.

Reads nodes and relationships out of the cartography temp database (always
Neo4j) and hands them to the configured sink (Neo4j or Neptune) in batches.
Backend-specific Cypher (MERGE shape, ID strategy, indexes) lives in each
sink; this module owns the source read loop and per-batch grouping only.
"""

import json
import time

from collections import defaultdict
from typing import Any

import neo4j

from celery.utils.log import get_task_logger

from api.attack_paths import database as graph_database
from api.attack_paths import sink as sink_module
from tasks.jobs.attack_paths.config import (
    PROVIDER_ISOLATION_PROPERTIES,
    PROVIDER_RESOURCE_LABEL,
    SYNC_BATCH_SIZE,
    get_provider_label,
    get_tenant_label,
)
from tasks.jobs.attack_paths.queries import (
    NODE_FETCH_QUERY,
    RELATIONSHIPS_FETCH_QUERY,
)

logger = get_task_logger(__name__)


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
    sink = sink_module.get_backend()
    sink.ensure_sync_indexes(target_database)

    nodes_synced = sync_nodes(
        source_database,
        target_database,
        tenant_id,
        provider_id,
        sink,
    )
    relationships_synced = sync_relationships(
        source_database,
        target_database,
        provider_id,
        sink,
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
    sink: Any,
) -> int:
    """
    Sync nodes from source to target database.

    Adds `_ProviderResource` label and dynamic `_Tenant_{id}` and `_Provider_{id}`
    isolation labels to all nodes.

    Source and target sessions are opened sequentially per batch to avoid
    holding two Bolt connections simultaneously for the entire sync duration.
    """
    t0 = time.perf_counter()
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

        for labels, batch in grouped.items():
            label_set = set(labels)
            label_set.add(PROVIDER_RESOURCE_LABEL)
            label_set.add(get_tenant_label(tenant_id))
            label_set.add(get_provider_label(provider_id))
            node_labels = ":".join(f"`{label}`" for label in sorted(label_set))
            sink.write_nodes(target_database, node_labels, batch)

        total_synced += batch_count
        logger.info(
            f"Synced {total_synced} nodes from {source_database} to {target_database} in {time.perf_counter() - t0:.3f}s"
        )

    return total_synced


def sync_relationships(
    source_database: str,
    target_database: str,
    provider_id: str,
    sink: Any,
) -> int:
    """
    Sync relationships from source to target database.

    Source and target sessions are opened sequentially per batch to avoid
    holding two Bolt connections simultaneously for the entire sync duration.
    """
    t0 = time.perf_counter()
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

        for rel_type, batch in grouped.items():
            sink.write_relationships(target_database, rel_type, provider_id, batch)

        total_synced += batch_count
        logger.info(
            f"Synced {total_synced} relationships from {source_database} to {target_database} in {time.perf_counter() - t0:.3f}s"
        )

    return total_synced


def _node_to_sync_dict(
    record: neo4j.Record, provider_id: str
) -> tuple[tuple[str, ...], dict[str, Any]]:
    """Transform a source node record into a (grouping_key, sync_dict) pair."""
    props = dict(record["props"] or {})
    _strip_internal_properties(props)
    _normalize_sink_properties(props)
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
    _normalize_sink_properties(props)
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


def _normalize_sink_properties(props: dict[str, Any]) -> None:
    """Normalize property values to primitive Cypher literals for either sink.

    Attack-paths node and relationship properties are written as primitive
    scalars regardless of the active sink (Neo4j or Neptune). The convention
    is driven by Neptune's openCypher type restrictions, which reject list,
    map, temporal and spatial property values, but it is applied uniformly
    so that custom and predefined queries are portable across sinks without
    runtime rewriting.

    Concretely:
      - Temporal values (neo4j.time.{DateTime,Date,Time,Duration}) become
        their ISO-8601 string representation.
      - Spatial values (neo4j.spatial.Point and subclasses) become their
        WKT-style string representation.
      - Lists become a comma-delimited string, read back with `split(prop, ',')`
        inside queries.
      - Maps / dicts become a JSON-encoded string, read back with `CONTAINS`
        substring checks inside queries.
    """
    for key, value in list(props.items()):
        props[key] = _to_sink_property_value(value)


def _to_sink_property_value(value: Any) -> Any:
    if hasattr(value, "iso_format") and callable(value.iso_format):
        return value.iso_format()

    if type(value).__module__.startswith("neo4j.spatial"):
        return str(value)

    if isinstance(value, dict):
        # openCypher `SET` rejects map property values: encode as JSON so the structured payload
        # survives the round-trip and is queryable with `CONTAINS` substring checks
        return json.dumps(value, sort_keys=True, default=str)

    if isinstance(value, list):
        # openCypher `SET` rejects list/array property values: encode as a
        # delimited string read back with split() inside queries
        return ",".join(str(_to_sink_property_value(v)) for v in value)

    return value
