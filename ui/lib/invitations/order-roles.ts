import type { InvitationRoleOption } from "@/types/onboarding-invite";

const ADMIN_ROLE_NAME = "admin";

export const isAdminRole = (role: InvitationRoleOption) =>
  role.name.toLowerCase() === ADMIN_ROLE_NAME;

/** Admin first: the natural pick for a teammate who has to finish the setup. */
export function orderRolesAdminFirst(
  roles: InvitationRoleOption[],
): InvitationRoleOption[] {
  return [...roles].sort(
    (a, b) => Number(isAdminRole(b)) - Number(isAdminRole(a)),
  );
}
