"""Tests for the provider models.

`SimplifiedProvider` overrides `_should_exclude` to always keep `connected` and
`secret_type` in the serialized output, even as `None` -- unlike every other
`None` field, which the mixin drops. `ProvidersListResponse` uses bracket access
throughout, so it raises `KeyError` on malformed input rather than defaulting,
unlike its siblings in roles.py/scans.py.
"""

import pytest

from prowler_mcp_server.prowler_app.models.providers import (
    DetailedProvider,
    ProviderConnectionStatus,
    ProviderDeletionResult,
    ProvidersListResponse,
    SimplifiedProvider,
)
from tests.helpers.jsonapi import (
    jsonapi_document,
    jsonapi_relationship_many,
    jsonapi_resource,
)

PROVIDER_ATTRIBUTES = {
    "uid": "123456789012",
    "alias": "production",
    "provider": "aws",
    "connection": {"connected": True},
}


def test_simplified_provider_reads_core_fields():
    provider = SimplifiedProvider.from_api_response(
        jsonapi_resource("providers", "p1", PROVIDER_ATTRIBUTES)
    )

    assert provider.id == "p1"
    assert provider.uid == "123456789012"
    assert provider.alias == "production"
    assert provider.provider == "aws"
    assert provider.connected is True


def test_simplified_provider_always_sets_secret_type_to_none():
    """`secret_type` is hardcoded to None in from_api_response -- populated
    separately via a secret endpoint, never derived here."""
    provider = SimplifiedProvider.from_api_response(
        jsonapi_resource("providers", "p1", PROVIDER_ATTRIBUTES)
    )

    assert provider.secret_type is None


def test_simplified_provider_connected_is_none_without_a_connection_block():
    provider = SimplifiedProvider.from_api_response(
        jsonapi_resource("providers", "p1", {"uid": "123", "provider": "aws"})
    )

    assert provider.connected is None


def test_simplified_provider_serialization_always_includes_connected_and_secret_type():
    """The custom _should_exclude override keeps connected/secret_type even when
    None, contrasting with a sibling field like `alias` which gets dropped."""
    provider = SimplifiedProvider.from_api_response(
        jsonapi_resource("providers", "p1", {"uid": "123", "provider": "aws"})
    )

    dumped = provider.model_dump()

    assert "connected" in dumped
    assert dumped["connected"] is None
    assert "secret_type" in dumped
    assert dumped["secret_type"] is None
    # alias is None too, but is NOT force-included -- normal mixin behavior applies.
    assert "alias" not in dumped


def test_detailed_provider_adds_temporal_fields():
    resource = jsonapi_resource(
        "providers",
        "p1",
        {
            **PROVIDER_ATTRIBUTES,
            "inserted_at": "2025-01-01T00:00:00Z",
            "updated_at": "2025-01-15T00:00:00Z",
            "connection": {
                "connected": True,
                "last_checked_at": "2025-01-15T00:00:00Z",
            },
        },
    )

    provider = DetailedProvider.from_api_response(resource)

    assert provider.inserted_at == "2025-01-01T00:00:00Z"
    assert provider.updated_at == "2025-01-15T00:00:00Z"
    assert provider.last_checked_at == "2025-01-15T00:00:00Z"


def test_detailed_provider_parses_provider_group_ids():
    resource = jsonapi_resource(
        "providers",
        "p1",
        attributes=PROVIDER_ATTRIBUTES,
        relationships={
            "provider_groups": jsonapi_relationship_many("provider-groups", "g1", "g2")
        },
    )

    provider = DetailedProvider.from_api_response(resource)

    assert provider.provider_group_ids == ["g1", "g2"]


def test_detailed_provider_group_ids_is_none_when_relationship_is_absent():
    provider = DetailedProvider.from_api_response(
        jsonapi_resource("providers", "p1", PROVIDER_ATTRIBUTES)
    )

    assert provider.provider_group_ids is None


def test_detailed_provider_group_ids_is_none_when_relationship_is_present_but_empty():
    """Unlike roles.py's `extract_relationship_ids` util (which distinguishes
    absent from present-but-empty), this hand-rolled extraction collapses both
    cases to None via a falsy-list check -- a documented divergence, not a bug
    to fix here."""
    resource = jsonapi_resource(
        "providers",
        "p1",
        attributes=PROVIDER_ATTRIBUTES,
        relationships={"provider_groups": jsonapi_relationship_many("provider-groups")},
    )

    provider = DetailedProvider.from_api_response(resource)

    assert provider.provider_group_ids is None


def test_providers_list_response_reads_pagination():
    response = jsonapi_document(
        data=[jsonapi_resource("providers", "p1", PROVIDER_ATTRIBUTES)],
        meta={"pagination": {"page": 1, "pages": 1, "count": 1}},
    )

    result = ProvidersListResponse.from_api_response(response)

    assert result.total_num_providers == 1
    assert result.providers[0].uid == "123456789012"


def test_providers_list_response_raises_on_missing_meta():
    """Unlike roles/scans list responses (which use .get() with defaults), this
    one uses bracket access throughout and raises KeyError on malformed input."""
    with pytest.raises(KeyError):
        ProvidersListResponse.from_api_response({"data": []})


def test_providers_list_response_raises_on_missing_pagination():
    with pytest.raises(KeyError):
        ProvidersListResponse.from_api_response({"data": [], "meta": {}})


def test_provider_deletion_result_is_constructed_directly():
    """No from_api_response -- built directly by the tool layer."""
    result = ProviderDeletionResult(
        status="deleted", message="Provider deleted successfully"
    )

    assert result.status == "deleted"
    assert result.task_id is None
    assert "task_id" not in result.model_dump()


def test_provider_connection_status_maps_true_to_connected():
    status = ProviderConnectionStatus.create(
        provider_data=jsonapi_resource("providers", "p1", PROVIDER_ATTRIBUTES),
        connection_status={"connected": True},
    )

    assert status.connected == "connected"
    assert status.error is None


def test_provider_connection_status_maps_false_to_failed():
    status = ProviderConnectionStatus.create(
        provider_data=jsonapi_resource("providers", "p1", PROVIDER_ATTRIBUTES),
        connection_status={"connected": False, "error": "Access denied"},
    )

    assert status.connected == "failed"
    assert status.error == "Access denied"


def test_provider_connection_status_maps_missing_connected_to_not_tested():
    status = ProviderConnectionStatus.create(
        provider_data=jsonapi_resource("providers", "p1", PROVIDER_ATTRIBUTES),
        connection_status={},
    )

    assert status.connected == "not_tested"


def test_provider_connection_status_maps_explicit_none_to_not_tested():
    status = ProviderConnectionStatus.create(
        provider_data=jsonapi_resource("providers", "p1", PROVIDER_ATTRIBUTES),
        connection_status={"connected": None},
    )

    assert status.connected == "not_tested"
