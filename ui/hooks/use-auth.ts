import { useSession } from "next-auth/react";

export function useAuth() {
  const { data: session, status } = useSession();

  const isLoading = status === "loading";
  const isAuthenticated = !!session?.user;

  const permissions = session?.user?.permissions || {
    manage_users: false,
    manage_account: false,
    manage_providers: false,
    manage_scans: false,
    manage_integrations: false,
    manage_billing: false,
    unlimited_visibility: false,
  };

  const hasPermission = (permission: keyof typeof permissions) => {
    return permissions[permission] === true;
  };

  return {
    session,
    isLoading,
    isAuthenticated,
    user: session?.user,
    permissions,
    hasPermission,
  };
}
