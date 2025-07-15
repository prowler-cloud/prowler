import { useSession } from "next-auth/react";

export function useAuth() {
  const { data: session, status } = useSession();

  const isLoading = status === "loading";
  const isAuthenticated = !!session?.user;

  // Extract permissions from session
  const permissions = session?.user?.permissions || {
    manage_users: false,
    manage_account: false,
    manage_providers: false,
    manage_scans: false,
    manage_integrations: false,
    manage_billing: false,
    unlimited_visibility: false,
  };

  const roleName = session?.user?.roleName || null;
  const roleId = session?.user?.roleId || null;

  // Helper functions
  const hasPermission = (permission: keyof typeof permissions) => {
    return permissions[permission] === true;
  };

  const hasAnyPermission = (permissionsList: (keyof typeof permissions)[]) => {
    return permissionsList.some((permission) => hasPermission(permission));
  };

  // Check if can access roles (cannot if has unlimited_visibility)
  const canAccessRoles = !permissions.unlimited_visibility;

  return {
    session,
    isLoading,
    isAuthenticated,
    user: session?.user,
    permissions,
    roleName,
    roleId,
    hasPermission,
    hasAnyPermission,
    canAccessRoles,
  };
}
