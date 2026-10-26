import { renderHook } from "@testing-library/react";
import { beforeEach, describe, expect, it, vi } from "vitest";

const { useFeatureFlagEnabledMock } = vi.hoisted(() => ({
  useFeatureFlagEnabledMock: vi.fn(),
}));

vi.mock("posthog-js/react", () => ({
  useFeatureFlagEnabled: useFeatureFlagEnabledMock,
}));

import { useFeatureFlag, useFeatureFlagState } from "./client";
import { FEATURE_FLAG, FEATURE_FLAG_STATE } from "./shared";

describe("useFeatureFlagState", () => {
  beforeEach(() => {
    useFeatureFlagEnabledMock.mockReset();
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
      "pending (not initialized or still loading)",
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
