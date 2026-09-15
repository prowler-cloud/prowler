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
  // Offer "Invite your team" once, right before the checkpoint dialog. Off by
  // default so a deployment opts in (or decides per tenant).
  showInviteStep?: boolean;
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
  showInviteStep = false,
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

  // The invite step goes first and leaves the store open, so the checkpoint
  // dialog follows unchanged once it resolves.
  if (
    open &&
    showInviteStep &&
    !inviteResolved &&
    !isOnboardingInviteHandled()
  ) {
    return (
      <OnboardingInviteStep
        onDone={() => {
          markOnboardingInviteHandled();
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
