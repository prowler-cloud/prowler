"use client";

import { useRouter } from "next/navigation";
import { useEffect, useRef, useState } from "react";

import { getOrderedFlows } from "@/lib/onboarding";
import { useOnboardingSequenceStore } from "@/store/onboarding-sequence";
import { useProviderWizardStore } from "@/store/provider-wizard/store";

import { isCheckpointArmed, shouldFireCheckpoint } from "./checkpoint.logic";
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

interface OnboardingCheckpointWatcherProps {
  // Tri-state, driven by the SERVER provider fetch the layout already computes
  // (the same value passed to `OnboardingGate`): `true`/`false` from a
  // successful fetch, `undefined` when provider state is unknown (failed/
  // ambiguous fetch). Driving from this prop — not the UI store — avoids the
  // store-hydration false-fire: the store defaults to `false` and
  // `StoreInitializer` hydrates it to the real value on mount, so a user who
  // already has providers would otherwise see a spurious `false -> true` flip.
  hasProviders?: boolean;
}

// Layout-level watcher (sibling to OnboardingGate). It observes the server
// `hasProviders` signal via prop and opens the checkpoint dialog exactly once on
// a concrete `false -> true` flip that has not been handled. A user who already
// has providers receives `true` from the FIRST render (prev=undefined), which
// never fires; only a genuine first-connect transition during the session does.
//
// The provider wizard creates the provider record on its FIRST step, so the
// flip can land WHILE the wizard is still open. Opening the checkpoint then
// would close the wizard mid-flow (two Radix dialogs). To avoid that, the
// watcher LATCHES "armed" the moment a genuine flip is seen, but DEFERS opening
// the dialog until the wizard is closed. It re-evaluates whenever either the
// provider signal or the wizard-open signal changes.
//
// Renders the dialog only; all decision logic runs in a client effect so the
// server renders nothing and there is no hydration mismatch.
export function OnboardingCheckpointWatcher({
  hasProviders,
}: OnboardingCheckpointWatcherProps) {
  const router = useRouter();

  // The previous observed `hasProviders`. `undefined` means "first read, no
  // transition seen yet" — that case must NOT fire the checkpoint.
  const previous = useRef<boolean | undefined>(undefined);
  // Latches once a genuine first-connect flip is observed, so the checkpoint
  // can still fire after the wizard closes even though the flip already passed.
  const armed = useRef(false);
  const [open, setOpen] = useState(false);

  const wizardOpen = useProviderWizardStore((state) => state.isOpen);

  useEffect(() => {
    // An unknown provider signal (failed/ambiguous fetch) must stay inert and
    // must not disturb the tracked previous value, so a later concrete read can
    // still compare against the last known boolean. The wizard-open change can
    // also retrigger this effect with `hasProviders` unchanged.
    if (hasProviders !== undefined) {
      const was = previous.current;
      previous.current = hasProviders;
      if (
        isCheckpointArmed({
          prev: was,
          next: hasProviders,
          handled: isCheckpointHandled(),
        })
      ) {
        armed.current = true;
      }
    }

    if (
      armed.current &&
      shouldFireCheckpoint({
        // The flip was already captured into `armed`; re-assert the same
        // arming truth via prev=false/next=true so the pure rule stays the
        // single source of the firing decision.
        prev: false,
        next: true,
        handled: isCheckpointHandled(),
        wizardOpen,
      })
    ) {
      armed.current = false;
      setOpen(true);
    }
  }, [hasProviders, wizardOpen]);

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
