import { beforeEach, describe, expect, it, vi } from "vitest";

import { loadCrossProviderFrameworks } from "@/app/(prowler)/compliance/_lib/cross-provider-catalog";

import { getAiFrameworks } from "./ai-security";

vi.mock("@/actions/finding-groups", () => ({
  getLatestFindingGroups: vi.fn(),
}));
vi.mock("@/actions/overview", () => ({
  getCategoryOverview: vi.fn(),
  getFindingsBySeverity: vi.fn(),
  getFindingsByStatus: vi.fn(),
}));
vi.mock("@/actions/scans", () => ({ getScans: vi.fn() }));
vi.mock("@/app/(prowler)/compliance/_actions/cross-provider", () => ({
  getCrossProviderComplianceOverview: vi.fn(),
}));
vi.mock("@/app/(prowler)/compliance/_lib/cross-provider-catalog", () => ({
  loadCrossProviderFrameworks: vi.fn(),
}));

const withCatalog = (incomplete: boolean) =>
  vi.mocked(loadCrossProviderFrameworks).mockResolvedValue({
    frameworks: [],
    unavailable: false,
    incomplete,
  });

describe("getAiFrameworks", () => {
  beforeEach(() => {
    vi.mocked(loadCrossProviderFrameworks).mockReset();
  });

  it("hides the section when an incomplete catalog shows no AI framework", async () => {
    withCatalog(true);

    await expect(getAiFrameworks({})).resolves.toBeNull();
  });

  it("reports no AI framework installed when the complete catalog has none", async () => {
    withCatalog(false);

    await expect(getAiFrameworks({})).resolves.toEqual([]);
  });
});
