"""
Graph sync operations for Attack Paths.

Reads nodes and relationships out of the cartography temp database (always
Neo4j) and hands them to the configured sink (Neo4j or Neptune) in batches.
Backend-specific Cypher (MERGE shape, ID strategy, indexes) lives in each
sink; this module owns the source read loop, per-batch grouping, and the
list-property materialisation policy (see `NormalizedList`).

Each list-typed node property that appears in the provider's
`normalized_lists` catalog becomes a set of child item nodes connected to
the parent by a typed edge. A list-typed property that is not in the
catalog is serialised to a comma-delimited string and emits a one-time
warning per (label, property), surfacing Cartography fields that should be
added to the catalog.
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
    PROVIDER_CONFIGS,
    PROVIDER_ISOLATION_PROPERTIES,
    PROVIDER_RESOURCE_LABEL,
    SYNC_BATCH_SIZE,
    NormalizedList,
    get_provider_label,
    get_tenant_label,
)
from tasks.jobs.attack_paths.queries import (
    NODE_FETCH_QUERY,
    RELATIONSHIPS_FETCH_QUERY,
)

logger = get_task_logger(__name__)

# (label, property) tuples for which we've already emitted the
# "unnormalised list" warning. Module-level so the warning fires once per
# process, not once per node.
_WARNED_UNNORMALIZED: set[tuple[str, str]] = set()


def sync_graph(
    source_database: str,
    target_database: str,
    tenant_id: str,
    provider_id: str,
    provider_type: str,
) -> dict[str, int]:
    """
    Sync all nodes and relationships from source to target database.

    Args:
        `source_database`: The temporary scan database
        `target_database`: The tenant database
        `tenant_id`: The tenant ID for isolation
        `provider_id`: The provider ID for isolation
        `provider_type`: Provider type key (e.g. "aws"), used to resolve the
            `NormalizedList` catalog from `PROVIDER_CONFIGS`.

    Returns:
        Dict with counts of synced nodes, child item nodes, and relationships.
    """
    sink = sink_module.get_backend()
    sink.ensure_sync_indexes(target_database)

    normalized_lists = _resolve_normalized_lists(provider_type)

    node_result = sync_nodes(
        source_database,
        target_database,
        tenant_id,
        provider_id,
        sink,
        normalized_lists,
    )
    relationships_synced = sync_relationships(
        source_database,
        target_database,
        provider_id,
        sink,
    )

    return {
        "nodes": node_result["parents"],
        "child_nodes": node_result["children"],
        "relationships": relationships_synced + node_result["parent_child_rels"],
    }


def sync_nodes(
    source_database: str,
    target_database: str,
    tenant_id: str,
    provider_id: str,
    sink: Any,
    normalized_lists: list[NormalizedList],
) -> dict[str, int]:
    """
    Sync nodes from source to target database, exploding catalogued list
    properties into child nodes + parent->child edges.

    Adds `_ProviderResource` label and dynamic `_Tenant_{id}` and `_Provider_{id}`
    isolation labels to all nodes (parents and children alike).

    Source and target sessions are opened sequentially per batch to avoid
    holding two Bolt connections simultaneously for the entire sync duration.
    """
    t0 = time.perf_counter()
    last_id = -1
    parents_synced = 0
    children_synced = 0
    parent_child_rels = 0

    catalog = _build_catalog_index(normalized_lists)
    extra_labels = _build_extra_labels(tenant_id, provider_id)

    while True:
        parent_groups: dict[tuple[str, ...], list[dict[str, Any]]] = defaultdict(list)
        child_groups: dict[str, list[dict[str, Any]]] = defaultdict(list)
        rel_groups: dict[str, list[dict[str, Any]]] = defaultdict(list)
        batch_count = 0

        with graph_database.get_session(source_database) as source_session:
            result = source_session.run(
                NODE_FETCH_QUERY,
                {"last_id": last_id, "batch_size": SYNC_BATCH_SIZE},
            )
            for record in result:
                batch_count += 1
                last_id = record["internal_id"]
                key, parent_dict, children, rels = _node_to_sync_dict(
                    record, provider_id, catalog
                )
                parent_groups[key].append(parent_dict)
                for child in children:
                    child_groups[child["_child_label"]].append(child["row"])
                for rel in rels:
                    rel_groups[rel["rel_type"]].append(rel["row"])

        if batch_count == 0:
            break

        for labels, batch in parent_groups.items():
            sink.write_nodes(
                target_database, _render_labels(labels, extra_labels), batch
            )

        for child_label, batch in child_groups.items():
            sink.write_nodes(
                target_database,
                _render_labels((child_label,), extra_labels),
                batch,
            )
            children_synced += len(batch)

        for rel_type, batch in rel_groups.items():
            sink.write_relationships(target_database, rel_type, provider_id, batch)
            parent_child_rels += len(batch)

        parents_synced += batch_count
        logger.info(
            f"Synced {parents_synced} parents (+{children_synced} child items, "
            f"+{parent_child_rels} item rels) from {source_database} to "
            f"{target_database} in {time.perf_counter() - t0:.3f}s"
        )

    return {
        "parents": parents_synced,
        "children": children_synced,
        "parent_child_rels": parent_child_rels,
    }


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
    record: neo4j.Record,
    provider_id: str,
    catalog: dict[tuple[str, str], NormalizedList],
) -> tuple[
    tuple[str, ...],
    dict[str, Any],
    list[dict[str, Any]],
    list[dict[str, Any]],
]:
    """Transform a source node record into a (grouping_key, sync_dict, children, rels) tuple.

    Catalogued list properties are popped from `props` and emitted as child
    nodes + parent->child relationships.
    """
    props = dict(record["props"] or {})
    _strip_internal_properties(props)
    labels = tuple(sorted(set(record["labels"] or [])))
    parent_element_id = f"{provider_id}:{record['element_id']}"

    children, rels = _explode_catalogued_lists(
        labels, props, catalog, provider_id, parent_element_id
    )

    _normalize_sink_properties(props, labels)

    parent = {
        "provider_element_id": parent_element_id,
        "props": props,
    }
    return labels, parent, children, rels


def _explode_catalogued_lists(
    labels: tuple[str, ...],
    props: dict[str, Any],
    catalog: dict[tuple[str, str], NormalizedList],
    provider_id: str,
    parent_element_id: str,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """Pop catalogued list properties from `props` and produce child + rel emits.

    A node may carry multiple labels (e.g. `AWSPolicyStatement` plus
    `_AWSResource`); we check each label for catalog matches independently.
    Returns:
        - children: list of {"_child_label": str, "row": <node row>} dicts.
        - rels:     list of {"rel_type": str, "row": <rel row>} dicts.
    """
    children: list[dict[str, Any]] = []
    rels: list[dict[str, Any]] = []

    for label in labels:
        for key in list(props.keys()):
            spec = catalog.get((label, key))
            if spec is None:
                continue
            value = props.pop(key)
            if value is None:
                continue
            if not isinstance(value, list):
                # Catalogued but not actually a list this scan - fall back to
                # the generic normaliser so we don't lose the value.
                props[key] = value
                continue
            for item in value:
                child_value_key, child_props = _build_child_props(spec, item)
                if child_value_key is None:
                    continue
                child_element_id = _build_child_id(
                    provider_id, spec.child_label, child_value_key
                )
                children.append(
                    {
                        "_child_label": spec.child_label,
                        "row": {
                            "provider_element_id": child_element_id,
                            "props": child_props,
                        },
                    }
                )
                rels.append(
                    {
                        "rel_type": spec.rel_type,
                        "row": {
                            "start_element_id": parent_element_id,
                            "end_element_id": child_element_id,
                            "provider_element_id": (
                                f"{parent_element_id}::{spec.rel_type}::"
                                f"{child_element_id}"
                            ),
                            "props": {},
                        },
                    }
                )

    return children, rels


def _build_child_props(
    spec: NormalizedList, item: Any
) -> tuple[str | None, dict[str, Any]]:
    """Translate one list element into a child node's prop dict.

    Returns (dedup_key, props). The dedup_key is what makes two child nodes
    equal within (tenant, provider) - used to build `_provider_element_id`.
    For scalar mode, the dedup key is the value itself. For dict mode it is
    a stable concatenation of the mapped fields in `field_map` order.
    """
    if not spec.field_map:
        if isinstance(item, (dict, list)):
            # Defensive: caller marked this list as scalar but elements are
            # structured. Convert to a stable string so the value survives.
            value_str = json.dumps(item, sort_keys=True, default=str)
        else:
            value_str = str(item)
        return value_str, {"value": value_str}

    if not isinstance(item, dict):
        # Catalogued as dict-shape but got a scalar. Skip - caller will see
        # the value go missing and can fix the field_map.
        return None, {}

    props: dict[str, Any] = {}
    dedup_parts: list[str] = []
    for src_key, child_field in spec.field_map:
        raw = item.get(src_key)
        value_str = _to_sink_property_value(raw) if raw is not None else ""
        props[child_field] = value_str
        dedup_parts.append(f"{child_field}={value_str}")
    return "::".join(dedup_parts), props


def _build_child_id(provider_id: str, child_label: str, value_key: str) -> str:
    """Deterministic `_provider_element_id` for a list-item child node.

    Dedupes within (tenant, provider): multiple parents referencing the same
    value share one child node via the existing MERGE-on-_provider_element_id
    index in both sinks.
    """
    return f"{provider_id}::{child_label}::{value_key}"


def _build_catalog_index(
    normalized_lists: list[NormalizedList],
) -> dict[tuple[str, str], NormalizedList]:
    """Index the catalog by (source_label, source_property) for O(1) lookup."""
    return {
        (spec.source_label, spec.source_property): spec for spec in normalized_lists
    }


def _build_extra_labels(tenant_id: str, provider_id: str) -> tuple[str, ...]:
    return (
        PROVIDER_RESOURCE_LABEL,
        get_tenant_label(tenant_id),
        get_provider_label(provider_id),
    )


def _render_labels(base_labels: tuple[str, ...], extra_labels: tuple[str, ...]) -> str:
    """Render the Cypher label string for a node-write batch."""
    label_set = set(base_labels) | set(extra_labels)
    return ":".join(f"`{label}`" for label in sorted(label_set))


def _resolve_normalized_lists(provider_type: str) -> list[NormalizedList]:
    config = PROVIDER_CONFIGS.get(provider_type)
    if config is None:
        # Unknown provider: empty catalog. Any list-typed property will be
        # serialised to a comma-delimited string with one warning per
        # (label, property).
        logger.warning(
            "Provider type %s not in PROVIDER_CONFIGS; no normalized_lists active",
            provider_type,
        )
        return []
    return config.normalized_lists


def _rel_to_sync_dict(
    record: neo4j.Record, provider_id: str
) -> tuple[str, dict[str, Any]]:
    """Transform a source relationship record into a (grouping_key, sync_dict) pair."""
    props = dict(record["props"] or {})
    _strip_internal_properties(props)
    # Relationship properties go through the same primitive coercion as
    # nodes; catalog-driven materialisation applies to node properties only.
    _normalize_sink_properties(props, labels=None)
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


def _normalize_sink_properties(
    props: dict[str, Any], labels: tuple[str, ...] | None
) -> None:
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
      - Maps / dicts become a JSON-encoded string, read back with `CONTAINS`
        substring checks inside queries.
      - Lists become a comma-delimited string. Catalogued list properties
        are materialised as child item nodes upstream in
        `_explode_catalogued_lists` and never reach this point; any list
        seen here is uncatalogued, so we log a one-time warning per
        (label, property) to surface Cartography fields that should be
        added to the catalog.

    `labels` is only used for the warning message; pass `None` for
    relationship props (no label context).
    """
    for key, value in list(props.items()):
        if isinstance(value, list) and labels is not None:
            _warn_unnormalized_list(labels, key)
        props[key] = _to_sink_property_value(value)


def _warn_unnormalized_list(labels: tuple[str, ...], key: str) -> None:
    """Emit one warning per (label, property) tuple for the lifetime of the process."""
    for label in labels:
        token = (label, key)
        if token in _WARNED_UNNORMALIZED:
            continue
        _WARNED_UNNORMALIZED.add(token)
        logger.warning(
            "Unnormalized list property %s.%s reached sink as comma-string; "
            "add a NormalizedList entry to the provider catalog to explode it",
            label,
            key,
        )


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
