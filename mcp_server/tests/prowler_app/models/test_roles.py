"""Tests for the RBAC role models.

`DetailedRole` overrides `_should_exclude` to keep `unlimited_visibility=False`
and empty `permissions`/`user_ids`/`provider_group_ids` lists -- only `None`
excludes them, unlike the mixin's default which also drops empty lists.
`permissions` itself is derived by scanning ALL attributes for any `manage_*`
prefixed truthy key, schema-agnostically.
"""

from prowler_mcp_server.prowler_app.models.roles import (
    DetailedRole,
    RolesListResponse,
    SimplifiedRole,
    UserRolesResult,
)
from tests.helpers.jsonapi import (
    jsonapi_document,
    jsonapi_relationship_many,
    jsonapi_resource,
)

ROLE_ATTRIBUTES = {
    "name": "Security Admin",
    "permission_state": "limited",
    "manage_users": True,
    "manage_scans": True,
    "manage_providers": False,
    "unlimited_visibility": False,
}


def test_simplified_role_reads_core_fields():
    role = SimplifiedRole.from_api_response(
        jsonapi_resource("roles", "r1", ROLE_ATTRIBUTES)
    )

    assert role.id == "r1"
    assert role.name == "Security Admin"
    assert role.permission_state == "limited"


def test_detailed_role_derives_permissions_from_manage_prefixed_attributes():
    """Only manage_* keys that are truthy are included; manage_providers=False
    is correctly excluded, and non-manage_ keys are ignored entirely."""
    role = DetailedRole.from_api_response(
        jsonapi_resource("roles", "r1", ROLE_ATTRIBUTES)
    )

    assert set(role.permissions) == {"manage_users", "manage_scans"}
    assert "manage_providers" not in role.permissions


def test_detailed_role_permissions_is_an_empty_list_when_no_manage_keys_exist():
    """The list comprehension always returns a list, never None, even with zero
    matches -- distinct from provider_group_ids/user_ids, which can be None."""
    role = DetailedRole.from_api_response(
        jsonapi_resource("roles", "r1", {"name": "Read Only"})
    )

    assert role.permissions == []


def test_detailed_role_includes_a_non_bool_truthy_manage_value():
    """The check is `and enabled`, not `and enabled is True` -- any truthy value
    is treated as granted."""
    role = DetailedRole.from_api_response(
        jsonapi_resource("roles", "r1", {"name": "Odd Role", "manage_scans": "yes"})
    )

    assert "manage_scans" in role.permissions


def test_detailed_role_reads_unlimited_visibility_and_relationships():
    resource = jsonapi_resource(
        "roles",
        "r1",
        attributes=ROLE_ATTRIBUTES,
        relationships={
            "provider_groups": jsonapi_relationship_many("provider-groups", "g1"),
            "users": jsonapi_relationship_many("users", "u1", "u2"),
        },
    )

    role = DetailedRole.from_api_response(resource)

    assert role.unlimited_visibility is False
    assert role.provider_group_ids == ["g1"]
    assert role.user_ids == ["u1", "u2"]


def test_detailed_role_relationship_ids_are_none_when_absent():
    """extract_relationship_ids: an absent relationship key yields None,
    distinct from a present-but-empty one (which yields [])."""
    role = DetailedRole.from_api_response(
        jsonapi_resource("roles", "r1", ROLE_ATTRIBUTES)
    )

    assert role.provider_group_ids is None
    assert role.user_ids is None


def test_detailed_role_relationship_ids_are_empty_list_when_present_but_empty():
    resource = jsonapi_resource(
        "roles",
        "r1",
        attributes=ROLE_ATTRIBUTES,
        relationships={"provider_groups": jsonapi_relationship_many("provider-groups")},
    )

    role = DetailedRole.from_api_response(resource)

    assert role.provider_group_ids == []


def test_detailed_role_serialization_keeps_false_unlimited_visibility():
    """unlimited_visibility=False must survive serialization -- only None
    triggers the custom exclusion override."""
    role = DetailedRole.from_api_response(
        jsonapi_resource("roles", "r1", ROLE_ATTRIBUTES)
    )

    dumped = role.model_dump()

    assert dumped["unlimited_visibility"] is False


def test_detailed_role_serialization_keeps_empty_permissions_list():
    role = DetailedRole.from_api_response(
        jsonapi_resource("roles", "r1", {"name": "Read Only"})
    )

    dumped = role.model_dump()

    assert dumped["permissions"] == []


def test_detailed_role_serialization_drops_none_relationship_ids():
    """A field the override lists (provider_group_ids) is still dropped when
    None -- the override only widens the exception for empty/False, not None."""
    role = DetailedRole.from_api_response(
        jsonapi_resource("roles", "r1", ROLE_ATTRIBUTES)
    )

    dumped = role.model_dump()

    assert "provider_group_ids" not in dumped
    assert "user_ids" not in dumped
    # A field not in the override list still follows normal mixin exclusion.
    assert "inserted_at" not in dumped


def test_roles_list_response_carries_pagination_metadata():
    response = jsonapi_document(
        data=[jsonapi_resource("roles", "r1", ROLE_ATTRIBUTES)],
        meta={"pagination": {"page": 1, "pages": 3, "count": 25}},
    )

    result = RolesListResponse.from_api_response(response)

    assert result.total_num_roles == 25
    assert result.total_num_pages == 3
    assert result.roles[0].name == "Security Admin"


def test_roles_list_response_defaults_pages_to_zero_when_meta_is_missing():
    """Unlike muting.py's list response (which defaults pages to 1), this one
    defaults to 0 -- a documented inconsistency across the codebase."""
    result = RolesListResponse.from_api_response({"data": []})

    assert result.total_num_roles == 0
    assert result.total_num_pages == 0
    assert result.current_page == 1


def test_user_roles_result_build_derives_the_count():
    role = DetailedRole.from_api_response(
        jsonapi_resource("roles", "r1", ROLE_ATTRIBUTES)
    )

    result = UserRolesResult.build(user_id="u1", roles=[role])

    assert result.total_num_roles == 1
    assert result.roles[0].id == "r1"


def test_user_roles_result_serialization_keeps_empty_roles_list():
    """roles is always included, even when empty -- an explicit 'no roles'
    signal rather than an omitted field."""
    result = UserRolesResult.build(user_id="u1", roles=[])

    dumped = result.model_dump()

    assert dumped["roles"] == []
    assert dumped["total_num_roles"] == 0
