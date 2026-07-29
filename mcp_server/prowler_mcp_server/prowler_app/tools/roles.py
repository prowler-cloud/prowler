"""Role (RBAC) tools for Prowler MCP Server.

This module provides read tools for browsing roles and inspecting the role a
user holds, plus a tool for setting it.

A user holds exactly one role: the API resolves a user's permissions from a
single role (`get_role` in `api.rbac.permissions`) and the UI only ever assigns
one, so setting a role replaces the one the user currently holds instead of
adding to it.
"""

from typing import Any

from pydantic import Field

from prowler_mcp_server.prowler_app.models.roles import (
    DetailedRole,
    RolesListResponse,
    UserRolesResult,
)
from prowler_mcp_server.prowler_app.tools.base import BaseTool


class RolesTools(BaseTool):
    """Tools for RBAC role operations.

    Provides tools for:
    - prowler_list_roles: List the roles defined in the tenant
    - prowler_get_role: Get detailed information about a specific role by ID
    - prowler_get_user_roles: List the roles assigned to a specific user
    - prowler_set_user_role: Set the role a user holds (idempotent)
    """

    async def list_roles(
        self,
        page_size: int = Field(
            default=50, description="Number of results to return per page"
        ),
        page_number: int = Field(
            default=1, description="Page number to retrieve (1-indexed)"
        ),
    ) -> dict[str, Any]:
        """List the RBAC roles defined in the authenticated tenant.

        Use this to discover which roles exist and their permission scope before
        assigning one to a user. Returns LIGHTWEIGHT role information.

        Each role includes:
        - id: Prowler internal UUID (v4), used with `prowler_get_role` and the assignment tools
        - name: Human-readable role name
        - permission_state: Summary of what the role grants ('unlimited', 'limited' or 'none')

        For the concrete capabilities a role grants and the users/provider groups
        it relates to, use `prowler_get_role`.
        """
        self.api_client.validate_page_size(page_size)

        params: dict[str, Any] = {
            "fields[roles]": "name,permission_state",
            "page[number]": page_number,
            "page[size]": page_size,
        }

        clean_params = self.api_client.build_filter_params(params)

        api_response = await self.api_client.get("/roles", params=clean_params)
        simplified_response = RolesListResponse.from_api_response(api_response)

        return simplified_response.model_dump()

    async def get_role(
        self,
        role_id: str = Field(
            description="Prowler's internal UUID (v4) for the role to retrieve. Use `prowler_list_roles` to find role IDs if you only know a name."
        ),
    ) -> dict[str, Any]:
        """Retrieve detailed information about a specific role by its ID.

        Returns everything `prowler_list_roles` returns PLUS:
        - permissions: The management capabilities the role grants (only the enabled ones). Read `permission_state` for the authoritative summary: 'unlimited' means the role grants every capability, including any this deployment does not list individually

        - unlimited_visibility: Whether the role can see all providers or only its provider groups
        - provider_group_ids: Provider groups the role is scoped to (empty list means it is scoped to no provider group)
        - user_ids: Users the role is assigned to (empty list means it is assigned to no user)
        - inserted_at / updated_at: Lifecycle timestamps

        The `user_ids` and `provider_group_ids` fields are always present: an
        empty list means "none", not "unknown".

        Workflow:
        1. Use `prowler_list_roles` to browse roles and find the target role 'id'
        2. Use this tool with that 'id' to inspect exactly what the role grants
        """
        api_response = await self.api_client.get(f"/roles/{role_id}")
        detailed_role = DetailedRole.from_api_response(api_response["data"])

        return detailed_role.model_dump()

    async def get_user_roles(
        self,
        user_id: str = Field(
            description="Prowler's internal UUID (v4) for the user whose roles you want. Use `prowler_list_users` to find user IDs, or `prowler_get_current_user` for the caller."
        ),
    ) -> dict[str, Any]:
        """List the roles currently assigned to a specific user.

        Returns the user's roles with the concrete capabilities each one grants,
        so you can see what the user is allowed to do in the tenant. A user
        normally holds a single role.

        Note: this reads the user's record, so it requires MANAGE_USERS (the same
        permission `prowler_get_user` needs). Each role's `user_ids` and
        `provider_group_ids` are not resolved here; use `prowler_get_role` for a
        role's full assignment and provider-group scope.

        Workflow:
        1. Use `prowler_list_users` (or `prowler_get_current_user`) to find the user 'id'
        2. Use this tool to see which role they hold and what it grants
        3. Use `prowler_set_user_role` to change it
        """
        roles = await self._fetch_user_roles(user_id)

        return UserRolesResult.build(user_id=user_id, roles=roles).model_dump()

    async def set_user_role(
        self,
        user_id: str = Field(
            description="Prowler's internal UUID (v4) for the user whose role you want to set. Use `prowler_list_users` to find user IDs."
        ),
        role_id: str = Field(
            description="Prowler's internal UUID (v4) for the role the user should hold. Use `prowler_list_roles` to find role IDs."
        ),
    ) -> dict[str, Any]:
        """Set the role a user holds, replacing the role they had before.

        A user holds exactly one role in Prowler: their permissions are resolved
        from a single role, so granting a new one REPLACES the previous one
        instead of adding to it. To change what a user can do, set the role that
        grants the capabilities they should have.

        This tool is idempotent: if the user already holds only this role, it
        makes no change and reports `changed: false`. It always returns the
        user's up-to-date role after the operation.

        Note: this operation requires both MANAGE_ACCOUNT (to change role
        assignments) and MANAGE_USERS (to read the user's current role). The API
        rejects the change when it would leave the tenant without a user holding
        MANAGE_ACCOUNT; such rejections are surfaced as errors.

        Workflow:
        1. Use `prowler_list_roles` to find the role 'id' to grant
        2. Use `prowler_list_users` to find the target user 'id'
        3. Use this tool to set the user's role
        """
        current_roles = await self._fetch_user_roles(user_id)
        if [role.id for role in current_roles] == [role_id]:
            return UserRolesResult.build(
                user_id=user_id,
                roles=current_roles,
                changed=False,
                message=f"User {user_id} already holds role {role_id}; no change made.",
            ).model_dump()

        # The relationship endpoint accepts any well-formed UUID and silently
        # drops role IDs that do not exist in this tenant, which would leave the
        # user with no role at all. Confirm the role exists before replacing.
        try:
            await self.api_client.get(f"/roles/{role_id}")
        except Exception as e:
            raise ValueError(
                f"Role {role_id} could not be read ({e}), so user {user_id} was left "
                f"unchanged. Use `prowler_list_roles` to find a valid role ID."
            ) from e

        # PATCH replaces the user's whole role set with this single role, the
        # same call the Prowler UI makes when changing a user's role.
        await self.api_client.patch(
            f"/users/{user_id}/relationships/roles",
            json_data={"data": [{"type": "roles", "id": role_id}]},
        )

        # After the change, fetch the user's roles again to report the authoritative state
        updated_roles = await self._fetch_user_roles(user_id)

        return UserRolesResult.build(
            user_id=user_id,
            roles=updated_roles,
            changed=True,
            message=f"Role {role_id} set for user {user_id}.",
        ).model_dump()

    # Private helper methods

    async def _fetch_user_roles(self, user_id: str) -> list[DetailedRole]:
        """Fetch the roles currently assigned to a user.

        Uses a single `GET /users/{id}?include=roles` request and reads the
        role resources from the JSON:API `included` section. This request
        requires MANAGE_USERS (it reads the user record).

        The included role resources do not carry their `users` /
        `provider_groups` relationships, so the returned `DetailedRole`
        instances omit `user_ids` / `provider_group_ids` (unknown here)
        rather than reporting them as empty. Use `get_role` for a role's full
        assignment and provider-group scope.

        Args:
            user_id: The Prowler UUID of the user

        Returns:
            The user's roles as DetailedRole instances (empty list if none)
        """
        response = await self.api_client.get(
            f"/users/{user_id}", params={"include": "roles"}
        )
        included = response.get("included", []) or []

        return [
            DetailedRole.from_api_response(item)
            for item in included
            if item.get("type") == "roles"
        ]
