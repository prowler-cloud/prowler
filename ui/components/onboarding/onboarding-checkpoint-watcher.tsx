"use client";

import dynamic from "next/dynamic";
import { useRouter } from "next/navigation";
import { useState } from "react";

import { getOrderedFlows } from "@/lib/onboarding";
import {
  isOnboardingInviteHandled,
  markOnboardingInviteHandled,
} from "@/lib/onboarding/invite-marker";
import {
  CHECKPOINT_MARKER,
  useOnboardingCheckpointStore,
} from "@/store/onboarding-checkpoint";
import { useOnboardingSequenceStore } from "@/store/onboarding-sequence";

import { OnboardingCheckpointDialog } from "./onboarding-checkpoint-dialog";

// Loaded on demand: the step pulls the invitation form and its server
// actions, which this module (re-exported by the shared barrel) must not
// carry statically.
const OnboardingInviteStep = dynamic(
  () =>
    import("./onboarding-invite-step").then(
      (module) => module.OnboardingInviteStep,
    ),
  { ssr: false },
);

interface OnboardingCheckpointWatcherProps {
  // Scopes the invite step's local marker: the offer is per tenant, not per
  // browser. Without it the step is not offered.
  tenantId?: string | null;
}

// Sequence begins at the flow after `add-provider` (the gate).
const FIRST_FLOW_ID = "add-provider";

function markCheckpointHandled(): void {
  if (typeof window === "undefined") return;
  try {
    window.localStorage.setItem(CHECKPOINT_MARKER, "true");
  } catch {
    // Non-fatal: a re-shown checkpoint beats a thrown render.
  }
}

// Layout-level watcher: renders the checkpoint dialog when the store `open` flag is set.
export function OnboardingCheckpointWatcher({
  tenantId = null,
}: OnboardingCheckpointWatcherProps = {}) {
  const router = useRouter();
  const open = useOnboardingCheckpointStore((state) => state.open);
  // Session flag: the marker is written on resolve, but a state change is
  // what re-renders this component into the checkpoint dialog.
  const [inviteResolved, setInviteResolved] = useState(false);

  const handleContinue = () => {
    markCheckpointHandled(); // before navigation to prevent re-open on re-render
    useOnboardingCheckpointStore.getState().close();

    // Start at the flow immediately after the gate, not just any non-gate flow:
    // a future registry insertion before it must not be skipped past.
    const ordered = getOrderedFlows();
    const gateIndex = ordered.findIndex((flow) => flow.id === FIRST_FLOW_ID);
    const nextFlow = gateIndex >= 0 ? ordered[gateIndex + 1] : undefined;
    if (!nextFlow) return;

    useOnboardingSequenceStore.getState().startSequence(nextFlow.id);
    router.push(nextFlow.route);
  };

  const handleFinish = () => {
    markCheckpointHandled();
    useOnboardingCheckpointStore.getState().close();
  };

  // "Invite your team" goes first, once per tenant, and leaves the store
  // open, so the checkpoint dialog follows unchanged once it resolves.
  if (open && !inviteResolved && !isOnboardingInviteHandled(tenantId)) {
    return (
      <OnboardingInviteStep
        onDone={() => {
          markOnboardingInviteHandled(tenantId);
          setInviteResolved(true);
        }}
      />
    );
  }

  return (
    <OnboardingCheckpointDialog
      open={open}
      onContinue={handleContinue}
      onFinish={handleFinish}
    />
  );
}
