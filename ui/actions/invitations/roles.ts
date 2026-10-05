"use server";

import { getRoles } from "@/actions/roles";
import type { InvitationRoleOption } from "@/types/onboarding-invite";

const ROLES_PAGE_SIZE = 50;

// Roles an invitation can grant; empty when the read fails so a caller can
// fall back (skip, disable) rather than block.
export const getInvitationRoles = async (): Promise<InvitationRoleOption[]> => {
  const rolesData = await getRoles({ pageSize: ROLES_PAGE_SIZE });
  const roles: unknown = rolesData?.data;
  if (!Array.isArray(roles)) return [];
  return roles.flatMap((role) =>
    typeof role?.id === "string" && typeof role?.attributes?.name === "string"
      ? [{ id: role.id, name: role.attributes.name }]
      : [],
  );
};
