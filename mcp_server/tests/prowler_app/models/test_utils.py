"""Tests for the shared JSON:API response-parsing helpers.

These back every model's ``from_api_response()``, so they are foundation-level
rather than tied to any one feature.
"""

from prowler_mcp_server.prowler_app.models.utils import extract_relationship_ids
from tests.helpers.jsonapi import jsonapi_relationship_many, jsonapi_relationship_one


def test_an_absent_relationship_is_unknown_rather_than_empty():
    """A relationship the document never mentioned yields None, not [].

    Returning [] would tell an agent "this role is assigned to nobody" when the
    serializer simply did not expose the relationship -- for example a role
    included via `?include=roles`, which carries no `users`.
    """
    assert extract_relationship_ids({}, "users") is None


def test_a_present_but_empty_relationship_is_explicitly_empty():
    """An empty relationship yields [], which genuinely means "none"."""
    relationships = {"users": jsonapi_relationship_many("users")}

    assert extract_relationship_ids(relationships, "users") == []


def test_a_to_many_relationship_is_flattened_to_its_ids():
    """Linkage objects are reduced to the plain ids the tools pass around."""
    relationships = {"users": jsonapi_relationship_many("users", "u1", "u2")}

    assert extract_relationship_ids(relationships, "users") == ["u1", "u2"]


def test_a_to_one_relationship_is_returned_as_a_single_element_list():
    """To-one and to-many both return a list so callers need no shape check."""
    relationships = {"scan": jsonapi_relationship_one("scans", "s1")}

    assert extract_relationship_ids(relationships, "scan") == ["s1"]


def test_a_null_to_one_relationship_is_empty():
    """An explicitly null to-one link means "not related", not "unknown"."""
    relationships = {"scan": {"data": None}}

    assert extract_relationship_ids(relationships, "scan") == []


def test_members_without_an_id_are_discarded():
    """Malformed linkage must not surface as a None entry in the id list.

    A None id would flow into a tool's next request and produce a confusing
    404 rather than a clean, short list.
    """
    relationships = {"users": {"data": [{"type": "users", "id": "u1"}, {}]}}

    assert extract_relationship_ids(relationships, "users") == ["u1"]
