"use client";

import { useAuth } from "@/hooks/use-auth";
import {
  isPartialScanAvailable,
  isPartialScanTarget,
} from "@/lib/partial-scans";
import { isCloud } from "@/lib/shared/env";
import type { PartialScanTarget } from "@/types/partial-scans";

/** The target to re-check, or null when the feature or the row cannot offer it. */
export function usePartialScanTarget(
  target: Partial<PartialScanTarget> | null | undefined,
): PartialScanTarget | null {
  const { hasPermission } = useAuth();

  const isAvailable = isPartialScanAvailable({
    cloudEnabled: isCloud(),
    canManageScans: hasPermission("manage_scans"),
  });

  return isAvailable && isPartialScanTarget(target) ? target : null;
}
