"use client";

import { useState } from "react";

import { getInvitationRoles } from "@/actions/invitations/roles";
import { useMountEffect } from "@/hooks/use-mount-effect";
import type { InvitationRoleOption } from "@/types/onboarding-invite";

// Roles that have not arrived by then count as unavailable, so a request
// that never answers cannot hold a form behind an empty list.
const ROLES_TIMEOUT_MS = 5_000;

/** Roles an invitation can grant: `null` until the read settles, `[]` when it failed or timed out. */
export function useInvitationRoles(): InvitationRoleOption[] | null {
  const [roles, setRoles] = useState<InvitationRoleOption[] | null>(null);

  useMountEffect(() => {
    let active = true;
    let timer: ReturnType<typeof setTimeout> | undefined;
    // First answer wins: a late response or a timer after it is ignored.
    const settle = (loaded: InvitationRoleOption[]) => {
      if (!active) return;
      active = false;
      clearTimeout(timer);
      setRoles(loaded);
    };
    timer = setTimeout(() => settle([]), ROLES_TIMEOUT_MS);
    getInvitationRoles()
      .then(settle)
      .catch(() => settle([]));
    return () => {
      active = false;
      clearTimeout(timer);
    };
  });

  return roles;
}
