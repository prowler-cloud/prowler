"""Tests for the attack paths models.

Key edge cases: `AttackPathsGraphNode` branches on presence of "ProwlerFinding" in
labels when extracting severity/status fields from properties. `AttackPathScan` and
`SimplifiedScan` have a latent bug where provider_id field is non-Optional str but
`from_api_response` can pass None (would raise ValidationError). These tests pin
current behavior rather than fixing — appropriate for a coverage-only PR.
"""

import pytest
from pydantic import ValidationError

from prowler_mcp_server.prowler_app.models.attack_paths import (
    AttackPathCartographySchema,
    AttackPathQuery,
    AttackPathQueryParameter,
    AttackPathQueryResult,
    AttackPathScan,
    AttackPathScansListResponse,
    AttackPathsGraphNode,
    AttackPathsGraphRelationship,
)
from tests.helpers.jsonapi import (
    jsonapi_collection,
    jsonapi_document,
    jsonapi_relationship_one,
    jsonapi_resource,
)

SCAN_ATTRIBUTES = {
    "state": "completed",
    "progress": 100,
}

PROWLER_FINDING_NODE_DATA = {
    "labels": ["ProwlerFinding"],
    "properties": {
        "id": "f1",
        "severity": "high",
        "status": "FAIL",
        "status_extended": "Resource is non-compliant",
    },
}


def test_attack_path_scan_reads_core_fields():
    scan = AttackPathScan.from_api_response(
        jsonapi_resource(
            "attack-path-scans",
            "scan1",
            attributes=SCAN_ATTRIBUTES,
            relationships={"provider": jsonapi_relationship_one("providers", "p1")},
        )
    )

    assert scan.id == "scan1"
    assert scan.state == "completed"
    assert scan.progress == 100
    assert scan.provider_id == "p1"


def test_attack_path_scan_missing_provider_relationship_raises_validation_error():
    """provider_id field is str (non-Optional) but from_api_response can produce
    None when the provider relationship is absent — this raises ValidationError.
    This pins current behavior (a likely latent bug) rather than fixing it."""
    with pytest.raises(ValidationError):
        AttackPathScan.from_api_response(
            jsonapi_resource("attack-path-scans", "scan1", attributes=SCAN_ATTRIBUTES)
        )


def test_attack_path_scans_list_response_raises_on_missing_pagination():
    with pytest.raises(ValueError, match="Missing pagination metadata"):
        AttackPathScansListResponse.from_api_response({"data": []})


def test_attack_path_scans_list_response_parses_pagination():
    response = jsonapi_collection(
        [
            jsonapi_resource(
                "attack-path-scans",
                "scan1",
                attributes=SCAN_ATTRIBUTES,
                relationships={"provider": jsonapi_relationship_one("providers", "p1")},
            )
        ],
        page=2,
        pages=3,
        count=42,
    )

    result = AttackPathScansListResponse.from_api_response(response)

    assert result.current_page == 2
    assert result.total_num_pages == 3
    assert result.total_num_scans == 42
    assert len(result.scans) == 1


def test_attack_path_cartography_schema_reads_required_fields():
    schema = AttackPathCartographySchema.from_api_response(
        jsonapi_document(
            jsonapi_resource(
                "cartography-schema",
                "schema1",
                {
                    "provider": "aws",
                    "cartography_version": "1.0.0",
                    "schema_url": "https://example.com/schema.json",
                    "raw_schema_url": "https://raw.example.com/schema.json",
                },
            )
        )
    )

    assert schema.id == "schema1"
    assert schema.provider == "aws"
    assert schema.cartography_version == "1.0.0"
    assert schema.schema_url == "https://example.com/schema.json"
    assert schema.raw_schema_url == "https://raw.example.com/schema.json"
    assert schema.schema_content is None  # Never set by from_api_response


def test_attack_path_cartography_schema_missing_data_key_raises():
    """If data key is missing, response.get("data", {}) yields {}, then
    data["id"] raises KeyError (inconsistent with attributes.get() pattern)."""
    with pytest.raises(KeyError):
        AttackPathCartographySchema.from_api_response({})


def test_attack_path_query_parameter_reads_fields():
    param = AttackPathQueryParameter.from_api_response(
        {
            "name": "region",
            "label": "Cloud Region",
            "data_type": "string",
            "description": "The region to query",
            "placeholder": "us-east-1",
        }
    )

    assert param.name == "region"
    assert param.label == "Cloud Region"
    assert param.data_type == "string"
    assert param.description == "The region to query"
    assert param.placeholder == "us-east-1"


def test_attack_path_query_parameter_defaults_data_type():
    param = AttackPathQueryParameter.from_api_response(
        {"name": "region", "label": "Region"}
    )

    assert param.data_type == "string"


def test_attack_path_query_parses_nested_parameters():
    query = AttackPathQuery.from_api_response(
        jsonapi_resource(
            "attack-paths-query",
            "q1",
            {
                "name": "Find exposed resources",
                "description": "Query for exposed resources",
                "provider": "aws",
                "parameters": [
                    {"name": "region", "label": "Region"},
                    {"name": "service", "label": "Service"},
                ],
            },
        )
    )

    assert query.id == "q1"
    assert query.name == "Find exposed resources"
    assert len(query.parameters) == 2
    assert query.parameters[0].name == "region"


def test_attack_path_query_tolerates_missing_parameters():
    query = AttackPathQuery.from_api_response(
        jsonapi_resource(
            "attack-paths-query",
            "q1",
            {
                "name": "Find exposed resources",
                "description": "Query for exposed resources",
                "provider": "aws",
            },
        )
    )

    assert query.parameters == []


def test_attack_path_graph_node_with_prowler_finding_label_extracts_severity():
    """Severity/status/status_extended are ONLY extracted from properties when
    'ProwlerFinding' is in labels. This tests the truthy branch. The node shape
    is a flat dict with "labels"/"properties" keys -- not a JSON:API resource."""
    node = AttackPathsGraphNode.from_api_response(PROWLER_FINDING_NODE_DATA)

    assert node.resource_id == "f1"
    assert "ProwlerFinding" in node.labels
    assert node.severity == "high"
    assert node.status == "FAIL"
    assert node.status_extended == "Resource is non-compliant"


def test_attack_path_graph_node_without_prowler_finding_label_drops_severity():
    """Node without 'ProwlerFinding' in labels must NOT expose severity/status
    fields even if the properties dict contains them. This tests the falsy branch."""
    node = AttackPathsGraphNode.from_api_response(
        {
            "labels": ["AwsS3Bucket"],
            "properties": {
                "id": "res1",
                "severity": "high",  # Present in properties
                "status": "FAIL",  # Present in properties
                "name": "my-bucket",
            },
        }
    )

    assert node.resource_id == "res1"
    assert "ProwlerFinding" not in node.labels
    assert node.severity is None  # NOT extracted, even though in properties
    assert node.status is None  # NOT extracted
    assert node.status_extended is None


def test_attack_path_graph_relationship_requires_all_fields():
    rel = AttackPathsGraphRelationship.from_api_response(
        {
            "id": "rel1",
            "label": "depends_on",
            "source": "n1",
            "target": "n2",
        }
    )

    assert rel.id == "rel1"
    assert rel.label == "depends_on"
    assert rel.source == "n1"
    assert rel.target == "n2"


def test_attack_path_query_result_with_empty_graph_is_normalized():
    """Both empty nodes/relationships arrays and null attributes normalize to
    the same empty result structure."""
    result = AttackPathQueryResult.from_api_response(
        jsonapi_document(
            jsonapi_resource(
                "attack-paths-result",
                "r1",
                {"nodes": [], "relationships": []},
            )
        )
    )

    assert result.nodes == []
    assert result.relationships == []
    assert result.message is None  # Never set by from_api_response


def test_attack_path_query_result_with_null_attributes_is_normalized():
    """Null attributes is normalized to empty attributes dict, then to empty
    nodes/relationships. `jsonapi_resource`'s `attributes or {}` can't express a
    literal `null`, so the document is built by hand here."""
    result = AttackPathQueryResult.from_api_response(
        {"data": {"type": "attack-paths-result", "id": "r1", "attributes": None}}
    )

    assert result.nodes == []
    assert result.relationships == []
    assert result.message is None


def test_attack_path_query_result_with_missing_data_key_is_normalized():
    """`response.get("data")` with no "data" key at all is also normalized to an
    empty result rather than raising."""
    result = AttackPathQueryResult.from_api_response({})

    assert result.nodes == []
    assert result.relationships == []


def test_attack_path_query_result_with_populated_graph():
    response = jsonapi_document(
        jsonapi_resource(
            "attack-paths-result",
            "r1",
            {
                "nodes": [
                    {
                        "labels": ["AwsS3Bucket"],
                        "properties": {"id": "n1", "name": "bucket1"},
                    }
                ],
                "relationships": [
                    {"id": "rel1", "label": "contains", "source": "n1", "target": "n2"}
                ],
            },
        )
    )

    result = AttackPathQueryResult.from_api_response(response)

    assert len(result.nodes) == 1
    assert result.nodes[0].resource_id == "n1"
    assert len(result.relationships) == 1
    assert result.relationships[0].label == "contains"
