import { describe, expect, it, vi } from "vitest";

const { notFound } = vi.hoisted(() => ({
  notFound: vi.fn(() => {
    throw new Error("NOT_FOUND");
  }),
}));
vi.mock("next/navigation", () => ({ notFound }));
vi.mock("@/app/(prowler)/premium/_components", () => ({
  PremiumComparison: () => null,
}));
vi.mock("@/components/shared/premium-ctas", () => ({
  PremiumCtas: () => null,
}));
vi.mock("@/components/shadcn/content-layout", () => ({
  ContentLayout: () => null,
}));

import PremiumPage from "./page";

describe("Premium page availability", () => {
  it("is not found in Cloud deployments", () => {
    // Given
    vi.stubEnv("UI_CLOUD_ENABLED", "true");

    // When / Then
    expect(() => PremiumPage()).toThrow("NOT_FOUND");
  });
});
