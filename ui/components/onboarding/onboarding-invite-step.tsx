"use client";

import { useInvitationRoles } from "@/hooks/use-invitation-roles";
import { useMountEffect } from "@/hooks/use-mount-effect";
import {
  dispatchOnboardingInviteStep,
  ONBOARDING_STEP_OUTCOME,
} from "@/lib/onboarding/onboarding-events";

import { OnboardingInviteDialog } from "./onboarding-invite-dialog";

interface OnboardingInviteStepProps {
  onDone: () => void;
}

// Mounted only while the step is showing: loads the roles once, announces
// the impression once, and resolves through a sent invitation or a skip.
export function OnboardingInviteStep({ onDone }: OnboardingInviteStepProps) {
  // `null` until the roles settle: the invitation form takes its default
  // role from the list at mount, so the dialog renders once the list is known.
  // Without roles the dialog offers only the skip, so the checkpoint is never
  // blocked: not by a failed read, not by one that never answers.
  const roles = useInvitationRoles();

  useMountEffect(() => {
    dispatchOnboardingInviteStep({ outcome: ONBOARDING_STEP_OUTCOME.SHOWN });
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
