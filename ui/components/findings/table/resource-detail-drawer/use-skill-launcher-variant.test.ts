import { renderHook } from "@testing-library/react";
import { beforeEach, describe, expect, it, vi } from "vitest";

const { useFeatureFlagVariantMock } = vi.hoisted(() => ({
  useFeatureFlagVariantMock: vi.fn(),
}));

vi.mock("@/lib/feature-flags/client", () => ({
  useFeatureFlagVariant: useFeatureFlagVariantMock,
}));

import { useSkillLauncherVariant } from "./use-skill-launcher-variant";

describe("useSkillLauncherVariant", () => {
  beforeEach(() => {
    useFeatureFlagVariantMock.mockReset();
  });

  it("should read the skill launcher flag with card as the fallback", () => {
    useFeatureFlagVariantMock.mockReturnValue("card");

    renderHook(() => useSkillLauncherVariant());

    expect(useFeatureFlagVariantMock).toHaveBeenCalledWith(
      "finding-detail-skill-launcher",
      ["card", "dropdown"],
      "card",
    );
  });

  it.each([
    ["dropdown", "dropdown"],
    ["card", "card"],
  ])(
    "should return the %s variant the flag module resolves",
    (_label, variant) => {
      useFeatureFlagVariantMock.mockReturnValue(variant);

      const { result } = renderHook(() => useSkillLauncherVariant());

      expect(result.current).toBe(variant);
    },
  );
});
