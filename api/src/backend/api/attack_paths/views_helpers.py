import logging

from typing import Any, Iterable

import neo4j
from rest_framework.exceptions import APIException, PermissionDenied, ValidationError

from api.attack_paths import database as graph_database, AttackPathsQueryDefinition
from api.attack_paths.queries.schema import (
    CARTOGRAPHY_SCHEMA_METADATA,
    GITHUB_SCHEMA_URL,
    RAW_SCHEMA_URL,
)
from config.custom_logging import BackendLogger
from tasks.jobs.attack_paths.config import INTERNAL_LABELS, INTERNAL_PROPERTIES

logger = logging.getLogger(BackendLogger.API)


# Predefined query helpers


def normalize_query_payload(raw_data):
    if not isinstance(raw_data, dict):  # Let the serializer handle this
        return raw_data

    if "data" in raw_data and isinstance(raw_data.get("data"), dict):
        data_section = raw_data.get("data") or {}
        attributes = data_section.get("attributes") or {}
        payload = {
            "id": attributes.get("id", data_section.get("id")),
            "parameters": attributes.get("parameters"),
        }

        # Remove `None` parameters to allow defaults downstream
        if payload.get("parameters") is None:
            payload.pop("parameters")
        return payload

    return raw_data


def prepare_parameters(
    definition: AttackPathsQueryDefinition,
    provided_parameters: dict[str, Any],
    provider_uid: str,
    provider_id: str,
) -> dict[str, Any]:
    parameters = dict(provided_parameters or {})
    expected_names = {parameter.name for parameter in definition.parameters}
    provided_names = set(parameters.keys())

    unexpected = provided_names - expected_names
    if unexpected:
        raise ValidationError(
            {"parameters": f"Unknown parameter(s): {', '.join(sorted(unexpected))}"}
        )

    missing = expected_names - provided_names
    if missing:
        raise ValidationError(
            {
                "parameters": f"Missing required parameter(s): {', '.join(sorted(missing))}"
            }
        )

    clean_parameters = {
        "provider_uid": str(provider_uid),
        "provider_id": str(provider_id),
    }

    for definition_parameter in definition.parameters:
        raw_value = provided_parameters[definition_parameter.name]

        try:
            casted_value = definition_parameter.cast(raw_value)

        except (ValueError, TypeError) as exc:
            raise ValidationError(
                {
                    "parameters": (
                        f"Invalid value for parameter `{definition_parameter.name}`: {str(exc)}"
                    )
                }
            )

        clean_parameters[definition_parameter.name] = casted_value

    return clean_parameters


def execute_query(
    database_name: str,
    definition: AttackPathsQueryDefinition,
    parameters: dict[str, Any],
    provider_id: str,
) -> dict[str, Any]:
    try:
        graph = graph_database.execute_read_query(
            database=database_name,
            cypher=definition.cypher,
            parameters=parameters,
        )
        return _serialize_graph(graph, provider_id)

    except graph_database.WriteQueryNotAllowedException:
        raise PermissionDenied(
            "Attack Paths query execution failed: read-only queries are enforced"
        )

    except graph_database.GraphDatabaseQueryException as exc:
        logger.error(f"Query failed for Attack Paths query `{definition.id}`: {exc}")
        raise APIException(
            "Attack Paths query execution failed due to a database error"
        )


# Custom query helpers


def normalize_custom_query_payload(raw_data):
    if not isinstance(raw_data, dict):
        return raw_data

    if "data" in raw_data and isinstance(raw_data.get("data"), dict):
        data_section = raw_data.get("data") or {}
        attributes = data_section.get("attributes") or {}
        return {"query": attributes.get("query")}

    return raw_data


def execute_custom_query(
    database_name: str,
    cypher: str,
    provider_id: str,
) -> dict[str, Any]:
    try:
        graph = graph_database.execute_read_query(
            database=database_name,
            cypher=cypher,
        )
        serialized = _serialize_graph(graph, provider_id)
        return _truncate_graph(serialized)

    except graph_database.WriteQueryNotAllowedException:
        raise PermissionDenied(
            "Attack Paths query execution failed: read-only queries are enforced"
        )

    except graph_database.GraphDatabaseQueryException as exc:
        logger.error(f"Custom cypher query failed: {exc}")
        raise APIException(
            "Attack Paths query execution failed due to a database error"
        )


# Cartography schema helpers


def get_cartography_schema(
    database_name: str, provider_id: str
) -> dict[str, str] | None:
    try:
        with graph_database.get_session(
            database_name, default_access_mode=neo4j.READ_ACCESS
        ) as session:
            result = session.run(
                CARTOGRAPHY_SCHEMA_METADATA,
                {"provider_id": provider_id},
            )
            record = result.single()
    except graph_database.GraphDatabaseQueryException as exc:
        logger.error(f"Cartography schema query failed: {exc}")
        raise APIException(
            "Unable to retrieve cartography schema due to a database error"
        )

    if not record:
        return None

    module_name = record["module_name"]
    version = record["module_version"]
    provider = module_name.split(":")[1]

    return {
        "id": f"{provider}-{version}",
        "provider": provider,
        "cartography_version": version,
        "schema_url": GITHUB_SCHEMA_URL.format(version=version, provider=provider),
        "raw_schema_url": RAW_SCHEMA_URL.format(version=version, provider=provider),
    }


# Private helpers


def _truncate_graph(graph: dict[str, Any]) -> dict[str, Any]:
    if graph["total_nodes"] > graph_database.MAX_CUSTOM_QUERY_NODES:
        graph["truncated"] = True

        graph["nodes"] = graph["nodes"][: graph_database.MAX_CUSTOM_QUERY_NODES]
        kept_node_ids = {node["id"] for node in graph["nodes"]}

        graph["relationships"] = [
            rel
            for rel in graph["relationships"]
            if rel["source"] in kept_node_ids and rel["target"] in kept_node_ids
        ]

    return graph


def _serialize_graph(graph, provider_id: str) -> dict[str, Any]:
    nodes = []
    kept_node_ids = set()
    for node in graph.nodes:
        if node._properties.get("provider_id") != provider_id:
            continue

        kept_node_ids.add(node.element_id)
        nodes.append(
            {
                "id": node.element_id,
                "labels": _filter_labels(node.labels),
                "properties": _serialize_properties(node._properties),
            },
        )

    relationships = []
    for relationship in graph.relationships:
        if relationship._properties.get("provider_id") != provider_id:
            continue

        if (
            relationship.start_node.element_id not in kept_node_ids
            or relationship.end_node.element_id not in kept_node_ids
        ):
            continue

        relationships.append(
            {
                "id": relationship.element_id,
                "label": relationship.type,
                "source": relationship.start_node.element_id,
                "target": relationship.end_node.element_id,
                "properties": _serialize_properties(relationship._properties),
            },
        )

    return {
        "nodes": nodes,
        "relationships": relationships,
        "total_nodes": len(nodes),
        "truncated": False,
    }


def _filter_labels(labels: Iterable[str]) -> list[str]:
    return [label for label in labels if label not in INTERNAL_LABELS]


def _serialize_properties(properties: dict[str, Any]) -> dict[str, Any]:
    """Convert Neo4j property values into JSON-serializable primitives.

    Filters out internal properties (Cartography metadata and provider
    isolation fields) defined in INTERNAL_PROPERTIES.
    """

    def _serialize_value(value: Any) -> Any:
        # Neo4j temporal and spatial values expose `to_native` returning Python primitives
        if hasattr(value, "to_native") and callable(value.to_native):
            return _serialize_value(value.to_native())

        if isinstance(value, (list, tuple)):
            return [_serialize_value(item) for item in value]

        if isinstance(value, dict):
            return {key: _serialize_value(val) for key, val in value.items()}

        return value

    return {
        key: _serialize_value(val)
        for key, val in properties.items()
        if key not in INTERNAL_PROPERTIES
    }


# Text serialization


def serialize_graph_as_text(graph: dict[str, Any]) -> str:
    """
    Convert a serialized graph dict into a compact text format for LLM consumption.

    Follows the incident-encoding pattern (nodes with context + sequential edges)
    which research shows is optimal for LLM path-reasoning tasks.

    Example::

        >>> serialize_graph_as_text({
        ...     "nodes": [
        ...         {"id": "n1", "labels": ["AWSAccount"], "properties": {"name": "prod"}},
        ...         {"id": "n2", "labels": ["EC2Instance"], "properties": {}},
        ...     ],
        ...     "relationships": [
        ...         {"id": "r1", "label": "RESOURCE", "source": "n1", "target": "n2", "properties": {}},
        ...     ],
        ...     "total_nodes": 2, "truncated": False,
        ... })
        ## Nodes (2)
        - AWSAccount "n1" (name: "prod")
        - EC2Instance "n2"

        ## Relationships (1)
        - AWSAccount "n1" -[RESOURCE]-> EC2Instance "n2"

        ## Summary
        - Total nodes: 2
        - Truncated: false
    """
    nodes = graph.get("nodes", [])
    relationships = graph.get("relationships", [])

    node_lookup = {node["id"]: node for node in nodes}

    lines = [f"## Nodes ({len(nodes)})"]
    for node in nodes:
        lines.append(f"- {_format_node_signature(node)}")

    lines.append("")
    lines.append(f"## Relationships ({len(relationships)})")
    for rel in relationships:
        lines.append(f"- {_format_relationship(rel, node_lookup)}")

    lines.append("")
    lines.append("## Summary")
    lines.append(f"- Total nodes: {graph.get('total_nodes', len(nodes))}")
    lines.append(f"- Truncated: {str(graph.get('truncated', False)).lower()}")

    return "\n".join(lines)


def _format_node_signature(node: dict[str, Any]) -> str:
    """
    Format a node as its reference followed by its properties.

    Example::

        >>> _format_node_signature({"id": "n1", "labels": ["AWSRole"], "properties": {"name": "admin"}})
        'AWSRole "n1" (name: "admin")'
        >>> _format_node_signature({"id": "n2", "labels": ["AWSAccount"], "properties": {}})
        'AWSAccount "n2"'
    """
    reference = _format_node_reference(node)
    properties = _format_properties(node.get("properties", {}))

    if properties:
        return f"{reference} {properties}"

    return reference


def _format_node_reference(node: dict[str, Any]) -> str:
    """
    Format a node as labels + quoted id (no properties).

    Example::

        >>> _format_node_reference({"id": "n1", "labels": ["EC2Instance", "NetworkExposed"]})
        'EC2Instance, NetworkExposed "n1"'
    """
    labels = ", ".join(node.get("labels", []))
    return f'{labels} "{node["id"]}"'


def _format_relationship(rel: dict[str, Any], node_lookup: dict[str, dict]) -> str:
    """
    Format a relationship as source -[LABEL (props)]-> target.

    Example::

        >>> _format_relationship(
        ...     {"id": "r1", "label": "STS_ASSUMEROLE_ALLOW", "source": "n1", "target": "n2",
        ...      "properties": {"weight": 1}},
        ...     {"n1": {"id": "n1", "labels": ["AWSRole"]},
        ...      "n2": {"id": "n2", "labels": ["AWSRole"]}},
        ... )
        'AWSRole "n1" -[STS_ASSUMEROLE_ALLOW (weight: 1)]-> AWSRole "n2"'
    """
    source = _format_node_reference(node_lookup[rel["source"]])
    target = _format_node_reference(node_lookup[rel["target"]])

    props = _format_properties(rel.get("properties", {}))
    label = f"{rel['label']} {props}" if props else rel["label"]

    return f"{source} -[{label}]-> {target}"


def _format_properties(properties: dict[str, Any]) -> str:
    """
    Format properties as a parenthesized key-value list.

    Returns an empty string when no properties are present.

    Example::

        >>> _format_properties({"name": "prod", "account_id": "123456789012"})
        '(name: "prod", account_id: "123456789012")'
        >>> _format_properties({})
        ''
    """
    if not properties:
        return ""

    parts = [f"{k}: {_format_value(v)}" for k, v in properties.items()]
    return f"({', '.join(parts)})"


def _format_value(value: Any) -> str:
    """
    Format a value using Cypher-style syntax (unquoted dict keys, lowercase bools).

    Example::

        >>> _format_value("prod")
        '"prod"'
        >>> _format_value(True)
        'true'
        >>> _format_value([80, 443])
        '[80, 443]'
        >>> _format_value({"env": "prod"})
        '{env: "prod"}'
        >>> _format_value(None)
        'null'
    """
    if isinstance(value, str):
        return f'"{value}"'

    if isinstance(value, bool):
        return str(value).lower()

    if isinstance(value, (list, tuple)):
        inner = ", ".join(_format_value(v) for v in value)
        return f"[{inner}]"

    if isinstance(value, dict):
        inner = ", ".join(f"{k}: {_format_value(v)}" for k, v in value.items())
        return f"{{{inner}}}"

    if value is None:
        return "null"

    return str(value)
