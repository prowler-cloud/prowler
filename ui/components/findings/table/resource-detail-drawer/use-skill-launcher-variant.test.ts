import { renderHook } from "@testing-library/react";
import { beforeEach, describe, expect, it, vi } from "vitest";

const { useFeatureFlagVariantKeyMock } = vi.hoisted(() => ({
  useFeatureFlagVariantKeyMock: vi.fn(),
}));

vi.mock("posthog-js/react", () => ({
  useFeatureFlagVariantKey: useFeatureFlagVariantKeyMock,
}));

import { useSkillLauncherVariant } from "./use-skill-launcher-variant";

describe("useSkillLauncherVariant", () => {
  beforeEach(() => {
    useFeatureFlagVariantKeyMock.mockReset();
  });

  it("should ask PostHog for the experiment flag", () => {
    useFeatureFlagVariantKeyMock.mockReturnValue(undefined);

    renderHook(() => useSkillLauncherVariant());

    expect(useFeatureFlagVariantKeyMock).toHaveBeenCalledWith(
      "finding-detail-skill-launcher",
    );
  });

  it("should return the dropdown variant when the flag resolves to it", () => {
    useFeatureFlagVariantKeyMock.mockReturnValue("dropdown");

    const { result } = renderHook(() => useSkillLauncherVariant());

    expect(result.current).toBe("dropdown");
  });

  it.each([
    ["card", "card"],
    ["unresolved flag", undefined],
    ["boolean flag", false],
    ["unknown variant", "weird"],
  ])("should fall back to card for %s", (_label, flagValue) => {
    useFeatureFlagVariantKeyMock.mockReturnValue(flagValue);

    const { result } = renderHook(() => useSkillLauncherVariant());

    expect(result.current).toBe("card");
  });
});
