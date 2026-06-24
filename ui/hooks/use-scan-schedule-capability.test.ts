import { renderHook } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";

import { SCAN_SCHEDULE_CAPABILITY } from "@/types/schedules";

import { useScanScheduleCapability } from "./use-scan-schedule-capability";

describe("useScanScheduleCapability", () => {
  afterEach(() => {
    vi.unstubAllEnvs();
  });

  it("returns DAILY_LEGACY for OSS without loading", () => {
    // Given
    vi.stubEnv("NEXT_PUBLIC_IS_CLOUD_ENV", "false");

    // When
    const { result } = renderHook(() => useScanScheduleCapability());

    // Then
    expect(result.current).toEqual({
      capability: SCAN_SCHEDULE_CAPABILITY.DAILY_LEGACY,
      isScheduleCapabilityLoading: false,
    });
  });

  it("returns ADVANCED for Cloud env without loading", () => {
    // Given
    vi.stubEnv("NEXT_PUBLIC_IS_CLOUD_ENV", "true");

    // When
    const { result } = renderHook(() => useScanScheduleCapability());

    // Then
    expect(result.current).toEqual({
      capability: SCAN_SCHEDULE_CAPABILITY.ADVANCED,
      isScheduleCapabilityLoading: false,
    });
  });

  it("honors explicit capability overrides", () => {
    // Given / When
    const { result } = renderHook(() =>
      useScanScheduleCapability(SCAN_SCHEDULE_CAPABILITY.MANUAL_ONLY),
    );

    // Then
    expect(result.current).toEqual({
      capability: SCAN_SCHEDULE_CAPABILITY.MANUAL_ONLY,
      isScheduleCapabilityLoading: false,
    });
  });
});
