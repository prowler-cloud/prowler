import { RolePermissionAttributes } from "@/types/users";

export const isUserOwnerAndHasManageAccount = (
  roles: any[],
  memberships: any[],
  userId: string,
): boolean => {
  const isOwner = memberships.some(
    (membership) =>
      membership.attributes.role === "owner" &&
      membership.relationships?.user?.data?.id === userId,
  );

  const hasManageAccount = roles.some(
    (role) =>
      role.attributes.manage_account === true &&
      role.relationships?.users?.data?.some((user: any) => user.id === userId),
  );

  return isOwner && hasManageAccount;
};

/**
 * Get the permissions for a user role
 * @param attributes - The attributes of the user role
 * @returns The permissions for the user role
 */
export const getRolePermissions = (attributes: RolePermissionAttributes) => {
  const permissions = [
    {
      key: "manage_users",
      label: "Manage Users",
      enabled: attributes.manage_users,
    },
    {
      key: "manage_account",
      label: "Manage Account",
      enabled: attributes.manage_account,
    },
    {
      key: "manage_providers",
      label: "Manage Providers",
      enabled: attributes.manage_providers,
    },
    {
      key: "manage_scans",
      label: "Manage Scans",
      enabled: attributes.manage_scans,
    },

    {
      key: "manage_integrations",
      label: "Manage Integrations",
      enabled: attributes.manage_integrations,
    },
    {
      key: "unlimited_visibility",
      label: "Unlimited Visibility",
      enabled: attributes.unlimited_visibility,
    },
  ];

  return permissions;
};
