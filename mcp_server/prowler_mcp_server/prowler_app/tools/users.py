"""User management tools for Prowler MCP Server.

This module provides read-only tools for viewing the users that belong to the
authenticated tenant, including identifying which user the current credentials
(API key or JWT) authenticate as.
"""

from typing import Any

from pydantic import Field

from prowler_mcp_server.prowler_app.models.users import (
    DetailedUser,
    UsersListResponse,
)
from prowler_mcp_server.prowler_app.tools.base import BaseTool


class UsersTools(BaseTool):
    """Tools for user management operations (read-only).

    Provides tools for:
    - prowler_list_users: List the users in the tenant with their names and emails
    - prowler_get_user: Get detailed information about a specific user by ID
    - prowler_get_current_user: Identify which user the current credentials authenticate as
    """

    async def list_users(
        self,
        name: str | None = Field(
            default=None,
            description="Filter by user display name. Partial match supported (case-insensitive).",
        ),
        email: str | None = Field(
            default=None,
            description="Filter by user email address. Partial match supported (case-insensitive).",
        ),
        page_size: int = Field(
            default=50, description="Number of results to return per page"
        ),
        page_number: int = Field(
            default=1, description="Page number to retrieve (1-indexed)"
        ),
    ) -> dict[str, Any]:
        """List the users that belong to the authenticated tenant.

        Use this to see who has access to the tenant and to look up their email
        addresses. Returns LIGHTWEIGHT user information optimized for browsing.

        Each user includes:
        - id: Prowler internal UUID (v4), used with `prowler_get_user`
        - name: Display name
        - email: Email address
        - company_name: Company the user belongs to, when set

        To find out which user the current credentials authenticate as, use
        `prowler_get_current_user`. For a single user's roles, membership links
        and join date, use `prowler_get_user`.
        """
        self.api_client.validate_page_size(page_size)

        params: dict[str, Any] = {
            "fields[users]": "name,email,company_name",
            "page[number]": page_number,
            "page[size]": page_size,
        }

        if name:
            params["filter[name__icontains]"] = name
        if email:
            params["filter[email__icontains]"] = email

        clean_params = self.api_client.build_filter_params(params)

        api_response = await self.api_client.get("/users", params=clean_params)
        simplified_response = UsersListResponse.from_api_response(api_response)

        return simplified_response.model_dump()

    async def get_user(
        self,
        user_id: str = Field(
            description="Prowler's internal UUID (v4) for the user to retrieve. Use `prowler_list_users` to find user IDs if you only know a name or email."
        ),
    ) -> dict[str, Any]:
        """Retrieve detailed information about a specific user by their ID.

        Returns everything `prowler_list_users` returns PLUS:
        - date_joined: When the user joined
        - role_ids: UUIDs of the roles assigned to the user
        - membership_ids: UUIDs of the user's tenant memberships

        Reading another user's roles/memberships requires MANAGE_ACCOUNT; without
        it the API hides them and `role_ids`/`membership_ids` are omitted rather
        than reported as empty.

        Workflow:
        1. Use `prowler_list_users` to browse users and find the target user 'id'
        2. Use this tool with that 'id' to inspect the user's roles and account details
        """
        api_response = await self.api_client.get(f"/users/{user_id}")
        detailed_user = DetailedUser.from_api_response(api_response["data"])

        return detailed_user.model_dump()

    async def get_current_user(self) -> dict[str, Any]:
        """Identify which user the current credentials authenticate as.

        Use this to determine the identity behind the credentials this MCP server
        is currently using, e.g. before performing actions on behalf of that user
        or when reporting who is connected.

        Returns the same detailed information as `prowler_get_user`:
        - id, name, email, company_name
        - date_joined
        - role_ids, membership_ids
        """
        api_response = await self.api_client.get("/users/me")
        detailed_user = DetailedUser.from_api_response(api_response["data"])

        return detailed_user.model_dump()
