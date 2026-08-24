"use client";

import { lazy, Suspense } from "react";

import { useRuntimeConfig } from "@/hooks/use-runtime-config";
import { isCloud } from "@/lib/shared/env";

const RuntimeFeedbackSurvey = lazy(() => import("./runtime-feedback-survey"));

export function FeedbackSurvey() {
  const { posthogEnabled, posthogKey, posthogHost } = useRuntimeConfig();

  if (!isCloud() || !posthogEnabled || !posthogKey || !posthogHost) return null;

  return (
    <Suspense fallback={null}>
      <RuntimeFeedbackSurvey
        key={`${posthogKey}:${posthogHost}`}
        posthogKey={posthogKey}
        posthogHost={posthogHost}
      />
    </Suspense>
  );
}
