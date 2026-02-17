from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest

from rest_framework.exceptions import APIException, ValidationError

from api.attack_paths import database as graph_database
from api.attack_paths import views_helpers


def test_normalize_run_payload_extracts_attributes_section():
    payload = {
        "data": {
            "id": "ignored",
            "attributes": {
                "id": "aws-rds",
                "parameters": {"ip": "192.0.2.0"},
            },
        }
    }

    result = views_helpers.normalize_run_payload(payload)

    assert result == {"id": "aws-rds", "parameters": {"ip": "192.0.2.0"}}


def test_normalize_run_payload_passthrough_for_non_dict():
    sentinel = "not-a-dict"
    assert views_helpers.normalize_run_payload(sentinel) is sentinel


def test_prepare_query_parameters_includes_provider_and_casts(
    attack_paths_query_definition_factory,
):
    definition = attack_paths_query_definition_factory(cast_type=int)
    result = views_helpers.prepare_query_parameters(
        definition,
        {"limit": "5"},
        provider_uid="123456789012",
    )

    assert result["provider_uid"] == "123456789012"
    assert result["limit"] == 5


@pytest.mark.parametrize(
    "provided,expected_message",
    [
        ({}, "Missing required parameter"),
        ({"limit": 10, "extra": True}, "Unknown parameter"),
    ],
)
def test_prepare_query_parameters_validates_names(
    attack_paths_query_definition_factory, provided, expected_message
):
    definition = attack_paths_query_definition_factory()

    with pytest.raises(ValidationError) as exc:
        views_helpers.prepare_query_parameters(definition, provided, provider_uid="1")

    assert expected_message in str(exc.value)


def test_prepare_query_parameters_validates_cast(
    attack_paths_query_definition_factory,
):
    definition = attack_paths_query_definition_factory(cast_type=int)

    with pytest.raises(ValidationError) as exc:
        views_helpers.prepare_query_parameters(
            definition,
            {"limit": "not-an-int"},
            provider_uid="1",
        )

    assert "Invalid value" in str(exc.value)


def test_execute_attack_paths_query_serializes_graph(
    attack_paths_query_definition_factory, attack_paths_graph_stub_classes
):
    definition = attack_paths_query_definition_factory(
        id="aws-rds",
        name="RDS",
        short_description="Short desc",
        description="",
        cypher="MATCH (n) RETURN n",
        parameters=[],
    )
    parameters = {"provider_uid": "123"}

    node = attack_paths_graph_stub_classes.Node(
        element_id="node-1",
        labels=["AWSAccount"],
        properties={
            "name": "account",
            "complex": {
                "items": [
                    attack_paths_graph_stub_classes.NativeValue("value"),
                    {"nested": 1},
                ]
            },
        },
    )
    relationship = attack_paths_graph_stub_classes.Relationship(
        element_id="rel-1",
        rel_type="OWNS",
        start_node=node,
        end_node=attack_paths_graph_stub_classes.Node("node-2", ["RDSInstance"], {}),
        properties={"weight": 1},
    )
    graph = SimpleNamespace(nodes=[node], relationships=[relationship])

    run_result = MagicMock()
    run_result.graph.return_value = graph

    session = MagicMock()
    session.run.return_value = run_result

    session_ctx = MagicMock()
    session_ctx.__enter__.return_value = session
    session_ctx.__exit__.return_value = False

    database_name = "db-tenant-test-tenant-id"

    with patch(
        "api.attack_paths.views_helpers.graph_database.get_session",
        return_value=session_ctx,
    ) as mock_get_session:
        result = views_helpers.execute_attack_paths_query(
            database_name, definition, parameters
        )

    mock_get_session.assert_called_once_with(database_name)
    session.run.assert_called_once_with(definition.cypher, parameters)
    assert result["nodes"][0]["id"] == "node-1"
    assert result["nodes"][0]["properties"]["complex"]["items"][0] == "value"
    assert result["relationships"][0]["label"] == "OWNS"


def test_execute_attack_paths_query_wraps_graph_errors(
    attack_paths_query_definition_factory,
):
    definition = attack_paths_query_definition_factory(
        id="aws-rds",
        name="RDS",
        short_description="Short desc",
        description="",
        cypher="MATCH (n) RETURN n",
        parameters=[],
    )
    database_name = "db-tenant-test-tenant-id"
    parameters = {"provider_uid": "123"}

    class ExplodingContext:
        def __enter__(self):
            raise graph_database.GraphDatabaseQueryException("boom")

        def __exit__(self, exc_type, exc, tb):
            return False

    with (
        patch(
            "api.attack_paths.views_helpers.graph_database.get_session",
            return_value=ExplodingContext(),
        ),
        patch("api.attack_paths.views_helpers.logger") as mock_logger,
    ):
        with pytest.raises(APIException):
            views_helpers.execute_attack_paths_query(
                database_name, definition, parameters
            )

    mock_logger.error.assert_called_once()
