"use client";

import { lazy, Suspense } from "react";

import { useRuntimeConfig } from "@/hooks/use-runtime-config";
import { isCloud } from "@/lib/shared/env";

const RuntimeFeedbackSurvey = lazy(() => import("./runtime-feedback-survey"));

export function FeedbackSurvey() {
  const { posthogEnabled, posthogKey, posthogIngestionHost, posthogUiHost } =
    useRuntimeConfig();

  if (!isCloud() || !posthogEnabled || !posthogKey || !posthogIngestionHost) {
    return null;
  }

  return (
    <Suspense fallback={null}>
      <RuntimeFeedbackSurvey
        key={`${posthogKey}:${posthogIngestionHost}:${posthogUiHost}`}
        posthogKey={posthogKey}
        posthogIngestionHost={posthogIngestionHost}
        posthogUiHost={posthogUiHost}
      />
    </Suspense>
  );
}
