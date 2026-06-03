"use client";

import type { Config } from "driver.js";
import { useSearchParams } from "next/navigation";
import { useState } from "react";

import { useMountEffect } from "@/hooks/use-mount-effect";
import { type OnboardingFlow } from "@/lib/onboarding";
import type { TourStepHandlers } from "@/lib/tours/tour-types";
import { useDriverTour } from "@/lib/tours/use-driver-tour";
import {
  type OnboardingSequenceMode,
  useOnboardingSequenceStore,
} from "@/store/onboarding-sequence";

import { resolveTriggerRequest } from "./onboarding-trigger.logic";

const ONBOARDING_PARAM = "onboarding";

interface OnboardingTriggerProps<TTarget extends string = string> {
  // The flow THIS route owns. The trigger force-starts it when the sequence
  // names it OR the `?onboarding=<id>` replay param matches.
  flow: OnboardingFlow;
  stepHandlers?: { [K in TTarget]?: TourStepHandlers<TTarget> };
  configOverrides?: Partial<Config>;
}

// A single latched trigger request. `key` lets us mount a FRESH runner per
// re-trigger so the tour can be restarted repeatedly; `mode` records whether
// the start came from the sequence or a replay param so the runner knows
// whether to strip the param.
interface OnboardingRequest {
  flow: OnboardingFlow;
  key: number;
  mode: OnboardingSequenceMode;
}

// Generalized per-route onboarding trigger. Reads the `?onboarding=<id>` replay
// param AND the sequence slice, DERIVES via `resolveTriggerRequest` whether this
// route's flow should force-start, then mounts a keyed runner over the real page
// surface. Renders nothing.
export function OnboardingTrigger<TTarget extends string = string>({
  flow,
  stepHandlers,
  configOverrides,
}: OnboardingTriggerProps<TTarget>) {
  const searchParams = useSearchParams();
  // `useSearchParams` can return null outside a router/Suspense context.
  const param = searchParams?.get(ONBOARDING_PARAM) ?? null;

  const sliceActive = useOnboardingSequenceStore((state) => state.active);
  const currentFlowId = useOnboardingSequenceStore(
    (state) => state.currentFlowId,
  );

  // DERIVED during render: does this route's flow want to start, and how?
  const resolved = resolveTriggerRequest({
    param,
    sliceActive,
    currentFlowId,
    flowId: flow.id,
  });
  // Collapse the resolving inputs to a single signal; `null` means "no start".
  const signal = resolved ? `${flow.id}:${resolved.mode}` : null;

  // The request is LATCHED so that stripping the replay param afterwards does
  // NOT unmount the runner (which previously destroyed the just-started tour).
  // We latch with React's "adjust state while rendering when an input changes"
  // pattern — the no-`useEffect` alternative — minting a fresh runner key only
  // on the transition INTO a new truthy signal. When the signal later drops to
  // `null` (param stripped) we only advance the tracker, leaving the runner up.
  const [request, setRequest] = useState<OnboardingRequest | null>(null);
  const [lastSignal, setLastSignal] = useState<string | null>(null);

  if (signal !== lastSignal) {
    setLastSignal(signal);
    if (resolved) {
      setRequest((prev) => ({
        flow,
        key: (prev?.key ?? 0) + 1,
        mode: resolved.mode,
      }));
    }
  }

  if (!request) return null;

  // Keyed so each re-trigger mounts a FRESH runner, preserving "restart works
  // repeatedly". The runner calls `useDriverTour` unconditionally, so Rules of
  // Hooks hold even though this parent can return null above.
  return (
    <OnboardingTourRunner<TTarget>
      key={request.key}
      flow={request.flow}
      mode={request.mode}
      stepHandlers={stepHandlers}
      configOverrides={configOverrides}
    />
  );
}

interface OnboardingTourRunnerProps<TTarget extends string> {
  flow: OnboardingFlow;
  mode: OnboardingSequenceMode;
  stepHandlers?: { [K in TTarget]?: TourStepHandlers<TTarget> };
  configOverrides?: Partial<Config>;
}

function OnboardingTourRunner<TTarget extends string>({
  flow,
  mode,
  stepHandlers,
  configOverrides,
}: OnboardingTourRunnerProps<TTarget>) {
  // The trigger only STARTS the current flow's tour on arrival. It no longer
  // owns sequence advance/exit: closing a tour in sequence mode leaves the
  // slice untouched, and the persistent OnboardingSequenceBanner is the single
  // control for Continue (advance + navigate) and Exit (stop). The `onClosed`
  // handler is intentionally inert for BOTH replay and sequence modes.
  const { start } = useDriverTour(flow.tour, {
    autoOpen: false,
    stepHandlers,
    configOverrides,
    onClosed: () => {
      // Intentionally inert: the banner is the single advance/exit control.
    },
  });

  // Mount-time side effects via the project-approved named wrapper (NOT a raw
  // `useEffect([])`): force-start the tour once, and for a replay strip the
  // `?onboarding` param via the History API so a hard reload does not re-launch
  // it. `replaceState` (not router.replace) avoids a `useSearchParams`
  // re-trigger / server round-trip, so the latched runner stays mounted.
  // Mounting a fresh runner per re-trigger (parent `key`) already guarantees
  // exactly one start per intentional trigger, including under React StrictMode.
  useMountEffect(() => {
    start();
    if (mode === "replay") {
      window.history.replaceState(null, "", window.location.pathname);
    }
  });

  return null;
}
