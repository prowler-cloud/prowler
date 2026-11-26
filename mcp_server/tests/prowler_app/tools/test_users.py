"""Tests for the user tools.

Reading another user's roles/memberships requires MANAGE_ACCOUNT; without it
the API omits those relationships rather than refusing the request, so
`get_user`/`get_current_user` must surface exactly what the API returned
without inventing a default for what it held back.
"""

import pytest
from fastmcp import Client

from tests.helpers.jsonapi import jsonapi_collection, jsonapi_document, jsonapi_resource

USERS = "/api/v1/users"
USER = "/api/v1/users/u1"
CURRENT_USER = "/api/v1/users/me"

USER_ATTRIBUTES = {
    "name": "Ada Lovelace",
    "email": "ada@example.com",
    "company_name": "Analytical Engines Inc",
}


async def test_list_users_applies_name_and_email_filters(
    mcp_root_server, mock_api_client, mock_router
):
    mock_router.add("GET", USERS, json=jsonapi_collection([]))

    async with Client(mcp_root_server) as client:
        await client.call_tool(
            "prowler_list_users", {"name": "Ada", "email": "ada@example.com"}
        )

    params = mock_router.query_params("GET", USERS)
    assert params["filter[name__icontains]"] == "Ada"
    assert params["filter[email__icontains]"] == "ada@example.com"


async def test_list_users_omits_filters_that_were_not_provided(
    mcp_root_server, mock_api_client, mock_router
):
    mock_router.add("GET", USERS, json=jsonapi_collection([]))

    async with Client(mcp_root_server) as client:
        await client.call_tool("prowler_list_users", {})

    params = mock_router.query_params("GET", USERS)
    assert "filter[name__icontains]" not in params
    assert "filter[email__icontains]" not in params


async def test_list_users_returns_the_simplified_fields(
    mcp_root_server, mock_api_client, mock_router
):
    mock_router.add(
        "GET",
        USERS,
        json=jsonapi_collection([jsonapi_resource("users", "u1", USER_ATTRIBUTES)]),
    )

    async with Client(mcp_root_server) as client:
        result = await client.call_tool("prowler_list_users", {})

    assert result.data["users"][0]["email"] == "ada@example.com"


async def test_get_user_returns_detailed_information(
    mcp_root_server, mock_api_client, mock_router
):
    mock_router.add(
        "GET",
        USER,
        json=jsonapi_document(jsonapi_resource("users", "u1", USER_ATTRIBUTES)),
    )

    async with Client(mcp_root_server) as client:
        result = await client.call_tool("prowler_get_user", {"user_id": "u1"})

    assert result.data["email"] == "ada@example.com"
    # No relationships in the document: hidden or genuinely none, either way
    # nothing is fabricated for it.
    assert "role_ids" not in result.data


async def test_get_current_user_reads_the_me_endpoint(
    mcp_root_server, mock_api_client, mock_router
):
    mock_router.add(
        "GET",
        CURRENT_USER,
        json=jsonapi_document(jsonapi_resource("users", "u1", USER_ATTRIBUTES)),
    )

    async with Client(mcp_root_server) as client:
        result = await client.call_tool("prowler_get_current_user", {})

    assert result.data["email"] == "ada@example.com"
    assert mock_router.paths() == ["GET " + CURRENT_USER]


async def test_get_user_requires_a_non_blank_user_id(
    mcp_root_server, mock_api_client, mock_router
):
    async with Client(mcp_root_server) as client:
        with pytest.raises(Exception):
            await client.call_tool("prowler_get_user", {"user_id": ""})

    assert mock_router.paths() == []
