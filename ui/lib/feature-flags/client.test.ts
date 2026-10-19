import { renderHook } from "@testing-library/react";
import { beforeEach, describe, expect, it, vi } from "vitest";

const { useFeatureFlagEnabledMock, useFeatureFlagVariantKeyMock } = vi.hoisted(
  () => ({
    useFeatureFlagEnabledMock: vi.fn(),
    useFeatureFlagVariantKeyMock: vi.fn(),
  }),
);

vi.mock("posthog-js/react", () => ({
  useFeatureFlagEnabled: useFeatureFlagEnabledMock,
  useFeatureFlagVariantKey: useFeatureFlagVariantKeyMock,
}));

import {
  useFeatureFlag,
  useFeatureFlagState,
  useFeatureFlagVariant,
} from "./client";
import { FEATURE_FLAG, FEATURE_FLAG_STATE } from "./shared";

const VARIANTS = ["card", "dropdown"] as const;

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

    renderHook(() => useFeatureFlag(FEATURE_FLAG.SKILL_LAUNCHER));

    expect(useFeatureFlagEnabledMock).toHaveBeenCalledWith(
      "finding-detail-skill-launcher",
    );
  });

  it("should return true when the flag is enabled", () => {
    useFeatureFlagEnabledMock.mockReturnValue(true);

    const { result } = renderHook(() =>
      useFeatureFlag(FEATURE_FLAG.SKILL_LAUNCHER),
    );

    expect(result.current).toBe(true);
  });

  it.each([
    ["disabled", false],
    ["unresolved (PostHog not initialized or still loading)", undefined],
  ])("should return false when the flag is %s", (_label, flagValue) => {
    useFeatureFlagEnabledMock.mockReturnValue(flagValue);

    const { result } = renderHook(() =>
      useFeatureFlag(FEATURE_FLAG.SKILL_LAUNCHER),
    );

    expect(result.current).toBe(false);
  });
});

describe("useFeatureFlagVariant", () => {
  beforeEach(() => {
    useFeatureFlagVariantKeyMock.mockReset();
  });

  it("should pass the flag key through to PostHog", () => {
    useFeatureFlagVariantKeyMock.mockReturnValue(undefined);

    renderHook(() =>
      useFeatureFlagVariant(FEATURE_FLAG.SKILL_LAUNCHER, VARIANTS, "card"),
    );

    expect(useFeatureFlagVariantKeyMock).toHaveBeenCalledWith(
      "finding-detail-skill-launcher",
    );
  });

  it("should return the resolved key when it is a known variant", () => {
    useFeatureFlagVariantKeyMock.mockReturnValue("dropdown");

    const { result } = renderHook(() =>
      useFeatureFlagVariant(FEATURE_FLAG.SKILL_LAUNCHER, VARIANTS, "card"),
    );

    expect(result.current).toBe("dropdown");
  });

  it.each([
    ["an unknown variant", "weird"],
    ["unresolved", undefined],
    ["a boolean value", true],
  ])("should fall back when the flag resolves to %s", (_label, flagValue) => {
    useFeatureFlagVariantKeyMock.mockReturnValue(flagValue);

    const { result } = renderHook(() =>
      useFeatureFlagVariant(FEATURE_FLAG.SKILL_LAUNCHER, VARIANTS, "card"),
    );

    expect(result.current).toBe("card");
  });
});
