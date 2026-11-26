"""Tests for the user models.

``DetailedUser`` deliberately distinguishes "no relationship data in the
document" from "the relationship is present and empty", because the API hides
another user's roles/memberships from a caller without MANAGE_ACCOUNT by
omitting the relationship rather than by refusing the request -- so an
observed empty list and a genuinely absent one cannot be treated the same.
"""

from prowler_mcp_server.prowler_app.models.users import (
    DetailedUser,
    SimplifiedUser,
    UsersListResponse,
)
from tests.helpers.jsonapi import (
    jsonapi_collection,
    jsonapi_relationship_many,
    jsonapi_resource,
)

USER_ATTRIBUTES = {
    "name": "Ada Lovelace",
    "email": "ada@example.com",
    "company_name": "Analytical Engines Inc",
}


def test_simplified_user_reads_the_core_identification_fields():
    user = SimplifiedUser.from_api_response(
        jsonapi_resource("users", "u1", USER_ATTRIBUTES)
    )

    assert user.id == "u1"
    assert user.name == "Ada Lovelace"
    assert user.email == "ada@example.com"
    assert user.company_name == "Analytical Engines Inc"


def test_simplified_user_tolerates_a_missing_company_name():
    user = SimplifiedUser.from_api_response(
        jsonapi_resource(
            "users", "u1", {"name": "Ada Lovelace", "email": "ada@example.com"}
        )
    )

    assert user.company_name is None
    assert "company_name" not in user.model_dump()


def test_detailed_user_parses_role_and_membership_relationships():
    resource = jsonapi_resource(
        "users",
        "u1",
        attributes={**USER_ATTRIBUTES, "date_joined": "2024-01-01T00:00:00Z"},
        relationships={
            "roles": jsonapi_relationship_many("roles", "r1", "r2"),
            "memberships": jsonapi_relationship_many("memberships", "m1"),
        },
    )

    user = DetailedUser.from_api_response(resource)

    assert user.role_ids == ["r1", "r2"]
    assert user.membership_ids == ["m1"]
    assert user.date_joined == "2024-01-01T00:00:00Z"


def test_detailed_user_omits_role_and_membership_ids_when_the_relationship_is_absent():
    """No `relationships` key at all: the caller lacks MANAGE_ACCOUNT and the API
    hid these entirely, distinct from genuinely having none."""
    user = DetailedUser.from_api_response(
        jsonapi_resource("users", "u1", USER_ATTRIBUTES)
    )

    assert user.role_ids is None
    assert user.membership_ids is None
    dumped = user.model_dump()
    assert "role_ids" not in dumped
    assert "membership_ids" not in dumped


def test_detailed_user_reports_an_explicitly_empty_relationship_as_an_empty_list():
    """`relationships` is present with no members: the user genuinely has none,
    which is a fact worth keeping distinct from "hidden"."""
    resource = jsonapi_resource(
        "users",
        "u1",
        attributes=USER_ATTRIBUTES,
        relationships={"roles": jsonapi_relationship_many("roles")},
    )

    user = DetailedUser.from_api_response(resource)

    assert user.role_ids == []


def test_users_list_response_carries_pagination_metadata():
    response = jsonapi_collection(
        [jsonapi_resource("users", "u1", USER_ATTRIBUTES)],
        page=2,
        pages=5,
        count=97,
    )

    result = UsersListResponse.from_api_response(response)

    assert result.current_page == 2
    assert result.total_num_pages == 5
    assert result.total_num_users == 97
    assert result.users[0].email == "ada@example.com"


def test_users_list_response_defaults_pagination_when_meta_is_missing():
    result = UsersListResponse.from_api_response({"data": []})

    assert result.total_num_users == 0
    assert result.total_num_pages == 0
    assert result.current_page == 1
    assert result.users == []
