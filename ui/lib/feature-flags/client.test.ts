import { renderHook } from "@testing-library/react";
import { beforeEach, describe, expect, it, vi } from "vitest";

const { useFeatureFlagEnabledMock, runtimeConfig } = vi.hoisted(() => ({
  useFeatureFlagEnabledMock: vi.fn(),
  runtimeConfig: { posthogKey: "phc_key" as string | null },
}));

vi.mock("posthog-js/react", () => ({
  useFeatureFlagEnabled: useFeatureFlagEnabledMock,
}));
vi.mock("@/hooks/use-runtime-config", () => ({
  useRuntimeConfig: () => runtimeConfig,
}));

import { useFeatureFlag, useFeatureFlagState } from "./client";
import { FEATURE_FLAG, FEATURE_FLAG_STATE } from "./shared";

describe("useFeatureFlagState", () => {
  beforeEach(() => {
    useFeatureFlagEnabledMock.mockReset();
    runtimeConfig.posthogKey = "phc_key";
  });

  it("should pass the flag key through to PostHog", () => {
    useFeatureFlagEnabledMock.mockReturnValue(undefined);

    renderHook(() => useFeatureFlagState(FEATURE_FLAG.ISSUES));

    expect(useFeatureFlagEnabledMock).toHaveBeenCalledWith("issues-feature");
  });

  it.each([
    ["on", true, FEATURE_FLAG_STATE.ON],
    ["off", false, FEATURE_FLAG_STATE.OFF],
    [
      "pending while PostHog loads flags",
      undefined,
      FEATURE_FLAG_STATE.PENDING,
    ],
  ])("should report %s", (_label, flagValue, expected) => {
    useFeatureFlagEnabledMock.mockReturnValue(flagValue);

    const { result } = renderHook(() =>
      useFeatureFlagState(FEATURE_FLAG.ISSUES),
    );

    expect(result.current).toBe(expected);
  });
});

describe("useFeatureFlagState without PostHog", () => {
  beforeEach(() => {
    useFeatureFlagEnabledMock.mockReset();
    useFeatureFlagEnabledMock.mockReturnValue(undefined);
  });

  it("should report off once mounted when no PostHog key is configured", () => {
    // Given: nothing will ever init PostHog (OSS, or PostHog disabled)
    runtimeConfig.posthogKey = null;

    // When
    const { result } = renderHook(() =>
      useFeatureFlagState(FEATURE_FLAG.ISSUES),
    );

    // Then: a flag nobody can turn on is off, not pending forever
    expect(result.current).toBe(FEATURE_FLAG_STATE.OFF);
  });

  it("should keep waiting while a configured PostHog has not loaded yet", () => {
    // Given: a key is set, so some client will init PostHog, maybe lazily
    runtimeConfig.posthogKey = "phc_key";

    // When
    const { result } = renderHook(() =>
      useFeatureFlagState(FEATURE_FLAG.ISSUES),
    );

    // Then
    expect(result.current).toBe(FEATURE_FLAG_STATE.PENDING);
  });
});

describe("useFeatureFlag", () => {
  beforeEach(() => {
    useFeatureFlagEnabledMock.mockReset();
  });

  it("should pass the flag key through to PostHog", () => {
    useFeatureFlagEnabledMock.mockReturnValue(undefined);

    renderHook(() => useFeatureFlag(FEATURE_FLAG.ISSUES));

    expect(useFeatureFlagEnabledMock).toHaveBeenCalledWith("issues-feature");
  });

  it("should return true when the flag is enabled", () => {
    useFeatureFlagEnabledMock.mockReturnValue(true);

    const { result } = renderHook(() => useFeatureFlag(FEATURE_FLAG.ISSUES));

    expect(result.current).toBe(true);
  });

  it.each([
    ["disabled", false],
    ["unresolved (PostHog not initialized or still loading)", undefined],
  ])("should return false when the flag is %s", (_label, flagValue) => {
    useFeatureFlagEnabledMock.mockReturnValue(flagValue);

    const { result } = renderHook(() => useFeatureFlag(FEATURE_FLAG.ISSUES));

    expect(result.current).toBe(false);
  });
});
