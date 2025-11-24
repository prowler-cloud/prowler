"""IAM & RBAC tools for Prowler App MCP Server - stub implementation."""

from prowler_mcp_server.prowler_app.utils.api_client import ProwlerAPIClient


# User management
async def list_team_members() -> dict[str, any]:
    """View all users in your Prowler tenant with their roles and access status.

    Returns:
        Paginated list of users with their roles and access status

    Raises:
        Exception: If API request fails
    """
    client = ProwlerAPIClient()
    return await client.get("/api/v1/users", params={"include": "roles"})


async def get_user_access_details(user_id: str) -> dict[str, any]:
    """Get comprehensive access information for a specific user.

    Args:
        user_id: UUID of the user to retrieve

    Returns:
        Comprehensive user details including all roles, permissions, and tenant memberships

    Raises:
        Exception: If API request fails
    """
    client = ProwlerAPIClient()
    return await client.get(
        f"/api/v1/users/{user_id}", params={"include": "roles,memberships"}
    )


# Role management
async def list_roles() -> dict[str, any]:
    """View all roles and their permissions in your Prowler tenant.

    Returns:
        List of roles with their permission settings and user assignments

    Raises:
        Exception: If API request fails
    """
    client = ProwlerAPIClient()
    return await client.get("/api/v1/roles")


# Stub functions for other IAM operations
async def update_user_roles(user_id: str, role_ids: list[str]) -> dict[str, any]:
    """Change role assignments for a user (stub).

    Args:
        user_id: UUID of the user to update
        role_ids: Role UUIDs to assign to the user

    Returns:
        Updated user with new role assignments

    Raises:
        NotImplementedError: Partial implementation
    """
    raise NotImplementedError("User role management needs additional implementation")


async def delete_user_access(user_id: str) -> dict[str, any]:
    """Remove a user from the Prowler tenant (stub).

    Args:
        user_id: UUID of the user to remove

    Returns:
        Confirmation of deletion

    Raises:
        NotImplementedError: Partial implementation
    """
    raise NotImplementedError("User deletion needs additional implementation")


async def invite_team_member(email: str, role_ids: list[str]) -> dict[str, any]:
    """Send an invitation to add a new team member (stub).

    Args:
        email: Email address to send invitation to
        role_ids: Role UUIDs to assign to the invited user

    Returns:
        The created invitation with token and expiration details

    Raises:
        NotImplementedError: Partial implementation
    """
    raise NotImplementedError("Team invitations need additional implementation")


async def list_pending_invitations() -> dict[str, any]:
    """View all team invitations and their status (stub).

    Returns:
        List of invitations with their status and role assignments

    Raises:
        NotImplementedError: Partial implementation
    """
    raise NotImplementedError("Invitation listing needs additional implementation")


async def revoke_invitation(invitation_id: str) -> dict[str, any]:
    """Cancel a pending invitation (stub).

    Args:
        invitation_id: UUID of the invitation to revoke

    Returns:
        Confirmation of revocation

    Raises:
        NotImplementedError: Partial implementation
    """
    raise NotImplementedError("Invitation revocation needs additional implementation")


async def create_custom_role(name: str) -> dict[str, any]:
    """Create a new role with specific permissions (stub).

    Args:
        name: Name for the new role

    Returns:
        The created role with all permission settings

    Raises:
        NotImplementedError: Partial implementation
    """
    raise NotImplementedError("Custom role creation needs additional implementation")


async def update_role_permissions(role_id: str) -> dict[str, any]:
    """Modify permissions for an existing role (stub).

    Args:
        role_id: UUID of the role to update

    Returns:
        The updated role with new permission settings

    Raises:
        NotImplementedError: Partial implementation
    """
    raise NotImplementedError("Role permission updates need additional implementation")


async def delete_role(role_id: str) -> dict[str, any]:
    """Permanently delete a role (stub).

    Args:
        role_id: UUID of the role to delete

    Returns:
        Confirmation of deletion

    Raises:
        NotImplementedError: Partial implementation
    """
    raise NotImplementedError("Role deletion needs additional implementation")
