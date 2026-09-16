"use client";

import { usePathname } from "next/navigation";
import { useCallback, useState, useSyncExternalStore } from "react";

import {
  skipOnboardingProfile,
  submitOnboardingProfile,
} from "@/actions/onboarding/profile";
import { useMountEffect } from "@/hooks/use-mount-effect";
import {
  dispatchOnboardingProfileStep,
  ONBOARDING_STEP_OUTCOME,
} from "@/lib/onboarding/onboarding-events";
import { shouldStartOnboardingProfile } from "@/lib/onboarding/profile-gate-decision";
import {
  getServerOnboardingProfileHandled,
  isOnboardingProfileHandled,
  markOnboardingProfileHandled,
  subscribeOnboardingProfileMarker,
} from "@/lib/onboarding/profile-marker";
import type { OnboardingProfileAnswers } from "@/types/onboarding-profile";

import { OnboardingGate } from "./onboarding-gate";
import { OnboardingProfileModal } from "./onboarding-profile-modal";

interface OnboardingProfileGateProps {
  // `undefined` = fetch failed/ambiguous; fail-open (never force the modal).
  hasProviders?: boolean;
  // Whether the API already holds the tenant's profile; `undefined` fails open.
  profileRecorded?: boolean;
  // Scopes the local marker: the step is per tenant, not per browser.
  tenantId?: string | null;
}

const isBillingPath = (pathname: string | null) =>
  pathname === "/billing" || pathname?.startsWith("/billing/") === true;

function ShownOnce() {
  useMountEffect(() => {
    dispatchOnboardingProfileStep({ outcome: ONBOARDING_STEP_OUTCOME.SHOWN });
  });
  return null;
}

// Profile step in front of the tour gate: the modal resolves first, then
// `OnboardingGate` takes over with the same `hasProviders` signal. Outcomes
// are announced as window events for whoever wants to observe them.
export function OnboardingProfileGate({
  hasProviders,
  profileRecorded,
  tenantId = null,
}: OnboardingProfileGateProps) {
  const pathname = usePathname();
  const handledLocally = useSyncExternalStore(
    subscribeOnboardingProfileMarker,
    // Bound per tenant so switching accounts re-reads the right key.
    useCallback(() => isOnboardingProfileHandled(tenantId), [tenantId]),
    getServerOnboardingProfileHandled,
  );
  // Session flag keeps the modal closed after submit/skip within this mount,
  // including the failure path where no marker is written.
  const [resolvedThisSession, setResolvedThisSession] = useState(false);
  const [isSubmitting, setIsSubmitting] = useState(false);

  const showProfile =
    // Billing must stay usable before onboarding; leaving it keeps the step eligible.
    !isBillingPath(pathname) &&
    !resolvedThisSession &&
    shouldStartOnboardingProfile({
      hasProviders,
      profileRecorded,
      handledLocally,
    });

  if (!showProfile) return <OnboardingGate hasProviders={hasProviders} />;

  const handleSubmit = async (answers: OnboardingProfileAnswers) => {
    setIsSubmitting(true);
    try {
      const result = await submitOnboardingProfile(answers);
      if (!result.stored) {
        // Nothing was written, so no marker and no submitted outcome: the
        // step returns on the next login instead of being lost.
        setResolvedThisSession(true);
        return;
      }
      dispatchOnboardingProfileStep({
        outcome: ONBOARDING_STEP_OUTCOME.SUBMITTED,
        answers,
      });
      markOnboardingProfileHandled(tenantId);
      setResolvedThisSession(true);
    } finally {
      setIsSubmitting(false);
    }
  };

  const handleSkip = async () => {
    setIsSubmitting(true);
    try {
      // A skip is a stored fact too, so it is only remembered locally once
      // the row exists.
      const result = await skipOnboardingProfile();
      if (result.stored) {
        dispatchOnboardingProfileStep({
          outcome: ONBOARDING_STEP_OUTCOME.SKIPPED,
        });
        markOnboardingProfileHandled(tenantId);
      }
      setResolvedThisSession(true);
    } finally {
      setIsSubmitting(false);
    }
  };

  return (
    <>
      <ShownOnce />
      <OnboardingProfileModal
        open
        isSubmitting={isSubmitting}
        onSubmit={handleSubmit}
        onSkip={handleSkip}
      />
    </>
  );
}
