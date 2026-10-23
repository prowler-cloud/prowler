"""Tests for the role (RBAC) tools.

``prowler_set_user_role`` replaces the single role a user holds, and the API
silently drops a role ID that does not exist in the tenant -- which would leave
the user with no role at all. So the tool reads the role first, and what that
read says has to be told apart carefully: only a not-found is about the role ID
the caller passed. A permission error, a rate limit or a server error is about
the request, and reporting either as "find a valid role ID" sends the user to
fix an ID that was fine.

Tools are driven through an in-memory MCP client so FastMCP resolves the
pydantic ``Field`` defaults and a raised failure arrives the way a client sees
it.
"""

import pytest
from fastmcp import Client

from tests.helpers.http import MockRouter
from tests.helpers.jsonapi import (
    jsonapi_document,
    jsonapi_error,
    jsonapi_resource,
)

USER = "/api/v1/users/u1"
USER_ROLES = f"{USER}/relationships/roles"
ROLE = "/api/v1/roles/r2"

ROLE_ATTRIBUTES = {"name": "admin", "manage_account": True}


def stub_user_holding(mock_router: MockRouter, role_id: str) -> MockRouter:
    """Serve ``GET /users/u1?include=roles`` with the user holding one role."""
    return mock_router.add(
        "GET",
        USER,
        json=jsonapi_document(
            jsonapi_resource("users", "u1", {"name": "Ada"}),
            included=[jsonapi_resource("roles", role_id, ROLE_ATTRIBUTES)],
        ),
    )


async def test_setting_a_role_the_user_already_holds_changes_nothing(
    mcp_root_server, mock_api_client, mock_router
):
    """Idempotent by design: no PATCH goes out, so nothing can be replaced."""
    stub_user_holding(mock_router, "r2")

    async with Client(mcp_root_server) as client:
        result = await client.call_tool(
            "prowler_set_user_role", {"user_id": "u1", "role_id": "r2"}
        )

    assert result.data["changed"] is False
    assert mock_router.paths() == [f"GET {USER}"]


async def test_a_role_that_does_not_exist_is_named_as_the_bad_argument(
    mcp_root_server, mock_api_client, mock_router
):
    """404 is the one answer that really is about the role ID.

    The PATCH would accept the ID and drop it, leaving the user with no role, so
    the read has to stop the call -- and say which ID to replace.
    """
    stub_user_holding(mock_router, "r1")
    mock_router.add("GET", ROLE, status=404, json=jsonapi_error(404, "Not found."))

    async with Client(mcp_root_server) as client:
        with pytest.raises(Exception, match="does not exist in this tenant") as raised:
            await client.call_tool(
                "prowler_set_user_role", {"user_id": "u1", "role_id": "r2"}
            )

    assert "left unchanged" in str(raised.value)
    assert f"PATCH {USER_ROLES}" not in mock_router.paths()


@pytest.mark.parametrize(
    ("status", "detail", "expected"),
    [
        (403, "Not allowed.", "not allowed to do this"),
        (429, "Slow down.", "rate limiting"),
        (500, "Boom.", "failed on Prowler's side"),
    ],
    ids=["forbidden", "rate-limited", "server-error"],
)
async def test_a_role_read_that_failed_for_another_reason_is_not_a_bad_role_id(
    mcp_root_server, mock_api_client, mock_router, status, detail, expected
):
    """These say nothing about the ID, so the classifier owns the message.

    Told "use prowler_list_roles to find a valid role ID", an agent goes looking
    for a role that was never the problem -- and finds the same wall.
    """
    stub_user_holding(mock_router, "r1")
    mock_router.add("GET", ROLE, status=status, json=jsonapi_error(status, detail))

    async with Client(mcp_root_server) as client:
        with pytest.raises(Exception, match=expected) as raised:
            await client.call_tool(
                "prowler_set_user_role", {"user_id": "u1", "role_id": "r2"}
            )

    assert "valid role ID" not in str(raised.value)
    assert f"PATCH {USER_ROLES}" not in mock_router.paths()


async def test_a_set_role_reports_the_role_the_user_holds_afterwards(
    mcp_root_server, mock_api_client, mock_router
):
    """The authoritative state is read back rather than assumed from the PATCH."""
    mock_router.add(
        "GET",
        USER,
        json=jsonapi_document(
            jsonapi_resource("users", "u1", {"name": "Ada"}),
            included=[jsonapi_resource("roles", "r1", ROLE_ATTRIBUTES)],
        ),
    )
    mock_router.add(
        "GET",
        USER,
        json=jsonapi_document(
            jsonapi_resource("users", "u1", {"name": "Ada"}),
            included=[jsonapi_resource("roles", "r2", ROLE_ATTRIBUTES)],
        ),
    )
    mock_router.add(
        "GET",
        ROLE,
        json=jsonapi_document(jsonapi_resource("roles", "r2", ROLE_ATTRIBUTES)),
    )
    mock_router.add("PATCH", USER_ROLES, status=204)

    async with Client(mcp_root_server) as client:
        result = await client.call_tool(
            "prowler_set_user_role", {"user_id": "u1", "role_id": "r2"}
        )

    assert result.data["changed"] is True
    assert [role["id"] for role in result.data["roles"]] == ["r2"]
    assert mock_router.json_body("PATCH", USER_ROLES) == {
        "data": [{"type": "roles", "id": "r2"}]
    }
