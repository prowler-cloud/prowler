"use client";

import { useState } from "react";

import { getOnboardingInviteRoles } from "@/actions/onboarding/invite";
import { useMountEffect } from "@/hooks/use-mount-effect";
import {
  dispatchOnboardingInviteStep,
  ONBOARDING_STEP_OUTCOME,
} from "@/lib/onboarding/onboarding-events";
import type { InvitationRoleOption } from "@/types/onboarding-invite";

import { OnboardingInviteDialog } from "./onboarding-invite-dialog";

interface OnboardingInviteStepProps {
  onDone: () => void;
}

// Roles that have not arrived by then count as unavailable, so a request
// that never answers cannot hold the checkpoint behind an empty step.
const ROLES_TIMEOUT_MS = 5_000;

// Mounted only while the step is showing: loads the roles once, announces
// the impression once, and resolves through a sent invitation or a skip.
export function OnboardingInviteStep({ onDone }: OnboardingInviteStepProps) {
  // `null` until the roles settle: the invitation form takes its default
  // role from the list at mount, so the dialog renders once the list is known.
  const [roles, setRoles] = useState<InvitationRoleOption[] | null>(null);

  useMountEffect(() => {
    dispatchOnboardingInviteStep({ outcome: ONBOARDING_STEP_OUTCOME.SHOWN });
    let active = true;
    let timer: ReturnType<typeof setTimeout> | undefined;
    // First answer wins: a late response or a timer after it is ignored.
    const settle = (loaded: InvitationRoleOption[]) => {
      if (!active) return;
      active = false;
      clearTimeout(timer);
      setRoles(loaded);
    };
    // Without roles the dialog offers only the skip, so the checkpoint is
    // never blocked: not by a failed read, not by one that never answers.
    timer = setTimeout(() => settle([]), ROLES_TIMEOUT_MS);
    getOnboardingInviteRoles()
      .then(settle)
      .catch(() => settle([]));
    return () => {
      active = false;
      clearTimeout(timer);
    };
  });

  if (roles === null) return null;

  return (
    <OnboardingInviteDialog
      open
      roles={roles}
      onSent={() => {
        dispatchOnboardingInviteStep({
          outcome: ONBOARDING_STEP_OUTCOME.SUBMITTED,
        });
        onDone();
      }}
      onSkip={() => {
        dispatchOnboardingInviteStep({
          outcome: ONBOARDING_STEP_OUTCOME.SKIPPED,
        });
        onDone();
      }}
    />
  );
}
