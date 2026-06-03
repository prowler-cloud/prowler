"use client";

import { useRouter } from "next/navigation";
import { useEffect, useRef, useState } from "react";

import { getOrderedFlows } from "@/lib/onboarding";
import { useOnboardingSequenceStore } from "@/store/onboarding-sequence";
import { useUIStore } from "@/store/ui/store";

import { shouldFireCheckpoint } from "./checkpoint.logic";
import { OnboardingCheckpointDialog } from "./onboarding-checkpoint-dialog";

// localStorage flag set once the user has either continued or finished the
// checkpoint. It keeps the dialog from re-appearing on any later provider flip
// in this browser. Distinct from per-tour `prowler.tour.*` completion records.
const CHECKPOINT_MARKER = "prowler.onboarding.checkpoint";

// The first ordered flow is `add-provider` (the gate). The checkpoint begins
// the sequence at the flow AFTER it, so any flow id but `add-provider` qualifies
// as the next one to start.
const FIRST_FLOW_ID = "add-provider";

function isCheckpointHandled(): boolean {
  if (typeof window === "undefined") return false;
  try {
    return window.localStorage.getItem(CHECKPOINT_MARKER) !== null;
  } catch {
    // Fail open: an unreadable storage should not block the checkpoint.
    return false;
  }
}

function markCheckpointHandled(): void {
  if (typeof window === "undefined") return;
  try {
    window.localStorage.setItem(CHECKPOINT_MARKER, "true");
  } catch {
    // Non-fatal: a re-shown checkpoint beats a thrown render.
  }
}

// Layout-level watcher (sibling to OnboardingGate). It observes `hasProviders`
// from the UI store — which `StoreInitializer` re-syncs on every layout render,
// including the post-connect re-fetch — and opens the checkpoint dialog exactly
// once on a concrete `false -> true` flip that has not been handled. Renders the
// dialog only; all decision logic runs in a client effect so the server renders
// nothing and there is no hydration mismatch.
export function OnboardingCheckpointWatcher() {
  const router = useRouter();
  const hasProviders = useUIStore((state) => state.hasProviders);

  // The previous observed `hasProviders`. `undefined` means "first read, no
  // transition seen yet" — that case must NOT fire the checkpoint.
  const previous = useRef<boolean | undefined>(undefined);
  const [open, setOpen] = useState(false);

  useEffect(() => {
    const was = previous.current;
    previous.current = hasProviders;
    if (
      shouldFireCheckpoint({
        prev: was,
        next: hasProviders,
        handled: isCheckpointHandled(),
      })
    ) {
      setOpen(true);
    }
  }, [hasProviders]);

  const handleContinue = () => {
    // Mark handled first so a re-render mid-navigation never re-opens it.
    markCheckpointHandled();
    setOpen(false);

    // Start at the first ordered flow that is NOT add-provider (i.e. the next
    // flow). Guard gracefully when none exists yet (registry may still be
    // add-provider-only until later slices add flows): close without crashing.
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
    setOpen(false);
  };

  return (
    <OnboardingCheckpointDialog
      open={open}
      onContinue={handleContinue}
      onFinish={handleFinish}
    />
  );
}
