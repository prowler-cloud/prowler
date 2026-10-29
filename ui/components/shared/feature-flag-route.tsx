"use client";

import { redirect } from "next/navigation";
import type { ReactNode } from "react";

import { FeatureFlagGate } from "@/components/shared/feature-flag-gate";
import type { FeatureFlag } from "@/lib/feature-flags";

const ToOverview = (): never => redirect("/");

interface FeatureFlagRouteProps {
  flag: FeatureFlag;
  children: ReactNode;
}

// A route behind a flag: off sends the user to the overview, pending renders
// nothing. Same client evaluation as the menu entry, so the link and the
// route never disagree.
export function FeatureFlagRoute({ flag, children }: FeatureFlagRouteProps) {
  return (
    <FeatureFlagGate flag={flag} fallback={<ToOverview />}>
      {children}
    </FeatureFlagGate>
  );
}
