import logging

from typing import Any, Iterable

from rest_framework.exceptions import APIException, ValidationError

from api.attack_paths import database as graph_database, AttackPathsQueryDefinition
from config.custom_logging import BackendLogger
from tasks.jobs.attack_paths.config import INTERNAL_LABELS

logger = logging.getLogger(BackendLogger.API)


def normalize_run_payload(raw_data):
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


def prepare_query_parameters(
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


def execute_attack_paths_query(
    database_name: str,
    definition: AttackPathsQueryDefinition,
    parameters: dict[str, Any],
    provider_id: str,
) -> dict[str, Any]:
    try:
        with graph_database.get_session(database_name) as session:
            result = session.run(definition.cypher, parameters)
            return _serialize_graph(result.graph(), provider_id)

    except graph_database.GraphDatabaseQueryException as exc:
        logger.error(f"Query failed for Attack Paths query `{definition.id}`: {exc}")
        raise APIException(
            "Attack Paths query execution failed due to a database error"
        )


def _serialize_graph(graph, provider_id: str):
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
    }


def _filter_labels(labels: Iterable[str]) -> list[str]:
    return [label for label in labels if label not in INTERNAL_LABELS]


def _serialize_properties(properties: dict[str, Any]) -> dict[str, Any]:
    """Convert Neo4j property values into JSON-serializable primitives."""

    def _serialize_value(value: Any) -> Any:
        # Neo4j temporal and spatial values expose `to_native` returning Python primitives
        if hasattr(value, "to_native") and callable(value.to_native):
            return _serialize_value(value.to_native())

        if isinstance(value, (list, tuple)):
            return [_serialize_value(item) for item in value]

        if isinstance(value, dict):
            return {key: _serialize_value(val) for key, val in value.items()}

        return value

    return {key: _serialize_value(val) for key, val in properties.items()}
