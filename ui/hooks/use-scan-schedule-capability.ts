"use client";

import { getScanScheduleCapability } from "@/lib/schedules";
import { isCloud } from "@/lib/shared/env";
import type { ScanScheduleCapability } from "@/types/schedules";

interface UseScanScheduleCapabilityResult {
  capability: ScanScheduleCapability;
  isScheduleCapabilityLoading: boolean;
}

export function useScanScheduleCapability(
  capabilityOverride?: ScanScheduleCapability,
): UseScanScheduleCapabilityResult {
  return {
    capability: capabilityOverride ?? getScanScheduleCapability(isCloud()),
    isScheduleCapabilityLoading: false,
  };
}
