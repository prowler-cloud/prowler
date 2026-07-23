"""Role (RBAC) tools for Prowler MCP Server.

This module provides read tools for browsing roles and inspecting the roles
assigned to a user, plus two convenience tools for assigning and removing a
role from a user. The assignment tools wrap Prowler's JSON:API relationship
endpoints (which have append/replace/remove semantics and several guard rails)
behind an idempotent, single-role interface so agents do not have to reason
about those low-level details.
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
    - prowler_assign_role_to_user: Assign a role to a user (idempotent)
    - prowler_remove_role_from_user: Remove a role from a user (idempotent)
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
        - permissions: The management capabilities the role grants (only the enabled ones)
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
        so you can see what the user is allowed to do in the tenant.

        Note: this reads the user's record, so it requires MANAGE_USERS (the same
        permission `prowler_get_user` needs). Each role's `user_ids` and
        `provider_group_ids` are not resolved here; use `prowler_get_role` for a
        role's full assignment and provider-group scope.

        Workflow:
        1. Use `prowler_list_users` (or `prowler_get_current_user`) to find the user 'id'
        2. Use this tool to see which roles they hold and what those roles grant
        3. Use `prowler_assign_role_to_user` / `prowler_remove_role_from_user` to change them
        """
        roles = await self._fetch_user_roles(user_id)

        return UserRolesResult.build(user_id=user_id, roles=roles).model_dump()

    async def assign_role_to_user(
        self,
        user_id: str = Field(
            description="Prowler's internal UUID (v4) for the user to assign the role to. Use `prowler_list_users` to find user IDs."
        ),
        role_id: str = Field(
            description="Prowler's internal UUID (v4) for the role to assign. Use `prowler_list_roles` to find role IDs."
        ),
    ) -> dict[str, Any]:
        """Assign a role to a user, keeping their other roles intact.

        This tool is idempotent: if the user already has the role, it makes no
        change and reports `changed: false`. It always returns the user's full,
        up-to-date role set after the operation.

        Note: this operation requires both MANAGE_ACCOUNT (to change role
        assignments) and MANAGE_USERS (to read the user's current roles). The API
        also enforces guard rails (for example, it keeps at least one user with
        MANAGE_ACCOUNT in the tenant); such rejections are surfaced as errors.

        Workflow:
        1. Use `prowler_list_roles` to find the role 'id' to grant
        2. Use `prowler_list_users` to find the target user 'id'
        3. Use this tool to assign the role
        """
        current_roles = await self._fetch_user_roles(user_id)
        if any(role.id == role_id for role in current_roles):
            return UserRolesResult.build(
                user_id=user_id,
                roles=current_roles,
                changed=False,
                message=f"Role {role_id} is already assigned to user {user_id}; no change made.",
            ).model_dump()

        # POST appends the role to the user's existing roles.
        await self.api_client.post(
            f"/users/{user_id}/relationships/roles",
            json_data={"data": [{"type": "roles", "id": role_id}]},
        )

        updated_roles = await self._fetch_user_roles(user_id)
        if not any(role.id == role_id for role in updated_roles):
            # The relationship endpoint silently ignores role IDs that don't
            # exist in this tenant (an unknown ID, or a role from another
            # tenant): it returns success without assigning anything. Detect that
            # here so we never report a change that did not actually happen.
            #
            # TODO: This should be a raise ValueError(...) instead of returning an error dict, but we don't have
            # a good standard for error handling in the tools yet. We should unify that across all tools.
            return {
                "error": f"Role {role_id} could not be assigned to user {user_id}: the role "
                f"was not found in this tenant. Use `prowler_list_roles` to find a "
                f"valid role ID."
            }

        return UserRolesResult.build(
            user_id=user_id,
            roles=updated_roles,
            changed=True,
            message=f"Role {role_id} assigned to user {user_id}.",
        ).model_dump()

    async def remove_role_from_user(
        self,
        user_id: str = Field(
            description="Prowler's internal UUID (v4) for the user to remove the role from. Use `prowler_list_users` to find user IDs."
        ),
        role_id: str = Field(
            description="Prowler's internal UUID (v4) for the role to remove. Use `prowler_get_user_roles` to see which roles the user currently holds."
        ),
    ) -> dict[str, Any]:
        """Remove a single role from a user, keeping their other roles intact.

        This tool is idempotent: if the user does not have the role, it makes no
        change and reports `changed: false`. It always returns the user's full,
        up-to-date role set after the operation.

        Note: this operation requires both MANAGE_ACCOUNT (to change role
        assignments) and MANAGE_USERS (to read the user's current roles). The API
        also enforces a guard rail — the last user holding MANAGE_ACCOUNT in the
        tenant cannot lose it; such rejections are surfaced as errors.

        Workflow:
        1. Use `prowler_get_user_roles` to see the user's current roles
        2. Use this tool with the role 'id' you want to remove
        """
        current_roles = await self._fetch_user_roles(user_id)
        if not any(role.id == role_id for role in current_roles):
            return UserRolesResult.build(
                user_id=user_id,
                roles=current_roles,
                changed=False,
                message=f"Role {role_id} is not assigned to user {user_id}; no change made.",
            ).model_dump()

        # The DELETE relationship endpoint cannot remove a single role reliably:
        # a JSON:API to-many payload is parsed as a list, which the API treats as
        # "clear all of the user's roles". Instead, PATCH the relationship with
        # the roles the user should keep, replacing the full set in one request.
        remaining_roles = [
            {"type": "roles", "id": role.id}
            for role in current_roles
            if role.id != role_id
        ]
        await self.api_client.patch(
            f"/users/{user_id}/relationships/roles",
            json_data={"data": remaining_roles},
        )

        updated_roles = await self._fetch_user_roles(user_id)
        return UserRolesResult.build(
            user_id=user_id,
            roles=updated_roles,
            changed=True,
            message=f"Role {role_id} removed from user {user_id}.",
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
