"use client";

import { useRouter } from "next/navigation";

import { getOrderedFlows } from "@/lib/onboarding";
import {
  CHECKPOINT_MARKER,
  useOnboardingCheckpointStore,
} from "@/store/onboarding-checkpoint";
import { useOnboardingSequenceStore } from "@/store/onboarding-sequence";

import { OnboardingCheckpointDialog } from "./onboarding-checkpoint-dialog";

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
export function OnboardingCheckpointWatcher() {
  const router = useRouter();
  const open = useOnboardingCheckpointStore((state) => state.open);

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

  return (
    <OnboardingCheckpointDialog
      open={open}
      onContinue={handleContinue}
      onFinish={handleFinish}
    />
  );
}
