"use client";

import { notFound } from "next/navigation";
import type { ReactNode } from "react";

import { FeatureFlagGate } from "@/components/shared/feature-flag-gate";
import type { FeatureFlag } from "@/lib/feature-flags";

const NotFound = (): never => notFound();

interface FeatureFlagRouteProps {
  flag: FeatureFlag;
  children: ReactNode;
}

// A route behind a flag: off answers 404, like a route that does not exist,
// and pending renders nothing. Same client evaluation as the menu entry, so
// the link and the route never disagree.
export function FeatureFlagRoute({ flag, children }: FeatureFlagRouteProps) {
  return (
    <FeatureFlagGate flag={flag} fallback={<NotFound />}>
      {children}
    </FeatureFlagGate>
  );
}
