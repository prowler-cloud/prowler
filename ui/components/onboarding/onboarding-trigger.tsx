"use client";

import type { Config } from "driver.js";
import { useRouter, useSearchParams } from "next/navigation";
import { useEffect, useRef, useState } from "react";

import { getOrderedFlows, type OnboardingFlow } from "@/lib/onboarding";
import type { TourStepHandlers } from "@/lib/tours/tour-types";
import { useDriverTour } from "@/lib/tours/use-driver-tour";
import {
  type OnboardingSequenceMode,
  useOnboardingSequenceStore,
} from "@/store/onboarding-sequence";

import {
  mapCloseToSequenceAction,
  resolveTriggerRequest,
} from "./onboarding-trigger.logic";

const ONBOARDING_PARAM = "onboarding";

interface OnboardingTriggerProps<TTarget extends string = string> {
  // The flow THIS route owns. The trigger force-starts it when the sequence
  // names it OR the `?onboarding=<id>` replay param matches.
  flow: OnboardingFlow;
  // Flow-specific step handlers (e.g. add-provider needs openWizard). Optional.
  stepHandlers?: { [K in TTarget]?: TourStepHandlers<TTarget> };
  // Per-flow driver config (e.g. shallow tours pass nothing). Optional.
  configOverrides?: Partial<Config>;
}

// A single latched trigger request. `key` lets us mount a FRESH runner per
// re-trigger so the tour can be restarted repeatedly; `mode` records whether
// the start came from the sequence or a replay param so the close handler knows
// whether to advance/stop the sequence or leave it untouched.
interface OnboardingRequest {
  flow: OnboardingFlow;
  key: number;
  mode: OnboardingSequenceMode;
}

// Generalized per-route onboarding trigger. Reads the `?onboarding=<id>` replay
// param AND the sequence slice, decides via `resolveTriggerRequest` whether this
// route's flow should force-start, then mounts a keyed runner over the real page
// surface. Renders nothing. Replaces the single-flow ProvidersOnboardingTrigger.
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

  // The request is LATCHED into state rather than derived from live params on
  // every render. Once latched, stripping the replay param does NOT unmount the
  // runner — which previously destroyed the just-started tour.
  const [request, setRequest] = useState<OnboardingRequest | null>(null);
  const keyRef = useRef(0);

  useEffect(() => {
    const resolved = resolveTriggerRequest({
      param,
      sliceActive,
      currentFlowId,
      flowId: flow.id,
    });
    if (!resolved) return;

    keyRef.current += 1;
    setRequest({ flow, key: keyRef.current, mode: resolved.mode });

    // For replay, strip the param via history so a hard reload does not
    // re-launch the tour. We use `window.history.replaceState` instead of
    // `router.replace` so clearing the param does NOT re-trigger
    // `useSearchParams` reactivity or a server route round-trip — the latched
    // runner therefore stays mounted. For sequence starts there is no param.
    if (resolved.mode === "replay") {
      window.history.replaceState(null, "", window.location.pathname);
    }
  }, [param, sliceActive, currentFlowId, flow]);

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
  const router = useRouter();

  const { start } = useDriverTour(flow.tour, {
    autoOpen: false,
    stepHandlers,
    configOverrides,
    onClosed: (state) => {
      // Replay is single-flow: never touch the sequence slice.
      if (mode === "replay") return;

      const action = mapCloseToSequenceAction(state);
      const sequence = useOnboardingSequenceStore.getState();
      if (action === "stop") {
        sequence.stop();
        return;
      }

      // Advance, then own the cross-route navigation (the slice stays
      // framework-agnostic). Resolve the next flow from the registry using the
      // pre-advance currentFlowId so navigation is deterministic.
      const ordered = getOrderedFlows();
      const currentIdx = ordered.findIndex((f) => f.id === flow.id);
      const nextFlow = currentIdx >= 0 ? ordered[currentIdx + 1] : undefined;
      sequence.advance();
      if (nextFlow) {
        router.push(nextFlow.route);
      }
    },
  });

  // Force-start once per mount. This bypasses the `hasCompleted` short-circuit
  // so re-trigger works even with an existing completion record.
  //
  // The empty dependency array is intentional (NOT `[start]`): `start` gets a
  // new identity every render and always reads the latest `driverRef.current`,
  // so a single call on mount is correct. A `hasStartedRef` guard must NOT be
  // used here: under React StrictMode (dev) the effect runs setup → cleanup →
  // setup; the first setup starts the tour, the cleanup destroys it, and a ref
  // guard would then skip the re-start on the second setup, leaving no visible
  // tour. Mounting a fresh runner per re-trigger (via the parent `key`) already
  // guarantees one start per intentional trigger.
  useEffect(() => {
    start();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  return null;
}
