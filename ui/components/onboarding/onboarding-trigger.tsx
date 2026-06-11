"use client";

import type { Config } from "driver.js";
import { useSearchParams } from "next/navigation";
import { useState } from "react";

import { useMountEffect } from "@/hooks/use-mount-effect";
import { type OnboardingFlow } from "@/lib/onboarding";
import { isCloud } from "@/lib/shared/env";
import type { TourStepHandlers } from "@/lib/tours/tour-types";
import { useDriverTour } from "@/lib/tours/use-driver-tour";
import { useOnboardingReplayStore } from "@/store/onboarding-replay";
import {
  type OnboardingSequenceMode,
  useOnboardingSequenceStore,
} from "@/store/onboarding-sequence";

import { resolveTriggerRequest } from "./onboarding-trigger.logic";

const ONBOARDING_PARAM = "onboarding";

function stripOnboardingParamFromLocation(queryString: string) {
  const params = new URLSearchParams(queryString);
  params.delete(ONBOARDING_PARAM);
  const query = params.toString();
  window.history.replaceState(
    null,
    "",
    `${window.location.pathname}${query ? `?${query}` : ""}${window.location.hash}`,
  );
}

interface OnboardingTriggerProps<TTarget extends string = string> {
  flow: OnboardingFlow; // force-started when the sequence names it or `?onboarding=<id>` matches
  stepHandlers?: { [K in TTarget]?: TourStepHandlers<TTarget> };
  configOverrides?: Partial<Config>;
}

// Latched per-trigger: `key` mounts a fresh runner on each re-trigger; `mode` drives param-strip logic.
interface OnboardingRequest {
  flow: OnboardingFlow;
  key: number;
  mode: OnboardingSequenceMode;
  queryString: string;
}

// Per-route trigger: derives via `resolveTriggerRequest` whether this flow should start,
// then mounts a keyed runner. Renders nothing.
export function OnboardingTrigger<TTarget extends string = string>({
  flow,
  stepHandlers,
  configOverrides,
}: OnboardingTriggerProps<TTarget>) {
  const searchParams = useSearchParams();
  const param = searchParams?.get(ONBOARDING_PARAM) ?? null; // null outside Suspense context
  const queryString = searchParams?.toString() ?? "";

  const sliceActive = useOnboardingSequenceStore((state) => state.active);
  const currentFlowId = useOnboardingSequenceStore(
    (state) => state.currentFlowId,
  );

  // In-memory replay request (same-route navbar click): starts the tour without a
  // `?onboarding=` URL param, so Next.js never refetches the page. `token` bumps on
  // every request so re-clicking the same flow yields a fresh signal.
  const replayRequestFlowId = useOnboardingReplayStore((state) => state.flowId);
  const replayToken = useOnboardingReplayStore((state) => state.token);

  // Cloud-only: in OSS the tour never resolves, so a manual `?onboarding=` URL can't start it.
  const resolved = isCloud()
    ? resolveTriggerRequest({
        param,
        replayRequestFlowId,
        sliceActive,
        currentFlowId,
        flowId: flow.id,
      })
    : null;
  // Token is part of the signal so a repeat same-route replay re-mints the key.
  // For param/sequence starts the token is stable, so behaviour is unchanged.
  const signal = resolved ? `${flow.id}:${resolved.mode}:${replayToken}` : null;

  // Latched via "adjust state while rendering" (no useEffect): mints a fresh key on each
  // new truthy signal; when signal drops to null (param stripped) the runner stays mounted.
  const [request, setRequest] = useState<OnboardingRequest | null>(null);
  const [lastSignal, setLastSignal] = useState<string | null>(null);

  if (signal !== lastSignal) {
    setLastSignal(signal);
    if (resolved) {
      setRequest((prev) => ({
        flow,
        key: (prev?.key ?? 0) + 1,
        mode: resolved.mode,
        queryString,
      }));
    }
  }

  if (!request) return null;

  // Keyed runner: fresh mount per re-trigger; `useDriverTour` is unconditional so hooks rules hold.
  return (
    <OnboardingTourRunner<TTarget>
      key={request.key}
      flow={request.flow}
      mode={request.mode}
      queryString={request.queryString}
      stepHandlers={stepHandlers}
      configOverrides={configOverrides}
    />
  );
}

interface OnboardingTourRunnerProps<TTarget extends string> {
  flow: OnboardingFlow;
  mode: OnboardingSequenceMode;
  queryString: string;
  stepHandlers?: { [K in TTarget]?: TourStepHandlers<TTarget> };
  configOverrides?: Partial<Config>;
}

function OnboardingTourRunner<TTarget extends string>({
  flow,
  mode,
  queryString,
  stepHandlers,
  configOverrides,
}: OnboardingTourRunnerProps<TTarget>) {
  // onClosed is intentionally inert — the banner owns advance/exit for both modes.
  const { start } = useDriverTour(flow.tour, {
    autoOpen: false,
    stepHandlers,
    configOverrides,
    onClosed: () => {},
  });

  // replaceState (not router.replace) avoids a useSearchParams re-trigger that would
  // drop the latched runner. The microtask keeps driver.js/flushSync outside
  // React's mount lifecycle.
  useMountEffect(() => {
    let cancelled = false;

    queueMicrotask(() => {
      if (cancelled) return;

      start();
      if (mode === "replay") {
        // Only strip when the param actually started this replay; a same-route
        // in-memory request leaves the URL untouched (no replaceState needed).
        if (new URLSearchParams(queryString).has(ONBOARDING_PARAM)) {
          stripOnboardingParamFromLocation(queryString);
        }
        // Clear any in-memory request so returning to this page won't auto-replay.
        useOnboardingReplayStore.getState().consume();
      }
    });

    return () => {
      cancelled = true;
    };
  });

  return null;
}
