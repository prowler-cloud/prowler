"use client";

import { useRouter } from "next/navigation";

import { getOrderedFlows } from "@/lib/onboarding";
import {
  CHECKPOINT_MARKER,
  useOnboardingCheckpointStore,
} from "@/store/onboarding-checkpoint";
import { useOnboardingSequenceStore } from "@/store/onboarding-sequence";

import { OnboardingCheckpointDialog } from "./onboarding-checkpoint-dialog";

// The first ordered flow is `add-provider` (the gate). The checkpoint begins
// the sequence at the flow AFTER it, so any flow id but `add-provider` qualifies
// as the next one to start.
const FIRST_FLOW_ID = "add-provider";

function markCheckpointHandled(): void {
  if (typeof window === "undefined") return;
  try {
    window.localStorage.setItem(CHECKPOINT_MARKER, "true");
  } catch {
    // Non-fatal: a re-shown checkpoint beats a thrown render.
  }
}

// Layout-level watcher (sibling to OnboardingGate). It subscribes to the
// onboarding-checkpoint store `open` flag and renders the checkpoint dialog when
// the flag is set. The flag is raised explicitly by the provider wizard on
// close (gated on `armed` + the handled marker), so this component owns no
// transition/flip detection — only the resolve actions (continue/finish).
export function OnboardingCheckpointWatcher() {
  const router = useRouter();
  const open = useOnboardingCheckpointStore((state) => state.open);

  const handleContinue = () => {
    // Mark handled first so a re-render mid-navigation never re-opens it.
    markCheckpointHandled();
    useOnboardingCheckpointStore.getState().close();

    // Start at the first ordered flow that is NOT add-provider (i.e. the next
    // flow). Guard gracefully when none exists yet: close without crashing.
    const nextFlow = getOrderedFlows().find(
      (flow) => flow.id !== FIRST_FLOW_ID,
    );
    if (!nextFlow) return;

    useOnboardingSequenceStore.getState().startSequence(nextFlow.id);
    router.push(nextFlow.route);
  };

  const handleFinish = () => {
    // Onboarding ends here: mark handled, start no sequence. Remaining flows
    // stay reachable via the avatar replay list.
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
