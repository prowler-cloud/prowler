import { beforeEach, describe, expect, it, vi } from "vitest";

const { getAllProviders, getAllProviderGroups, notFound } = vi.hoisted(() => ({
  getAllProviders: vi.fn(),
  getAllProviderGroups: vi.fn(),
  notFound: vi.fn(() => {
    throw new Error("NOT_FOUND");
  }),
}));
vi.mock("next/navigation", () => ({ notFound }));
vi.mock("@/actions/providers", () => ({ getAllProviders }));
vi.mock("@/actions/manage-groups/manage-groups", () => ({
  getAllProviderGroups,
}));
vi.mock("@/components/filters/provider-account-selectors", () => ({
  ProviderAccountSelectors: () => null,
}));
vi.mock("@/components/filters/provider-group-selector", () => ({
  ProviderGroupSelector: () => null,
}));
vi.mock("@/components/shadcn/content-layout", () => ({
  ContentLayout: () => null,
}));
vi.mock("./_components/issues-list", () => ({ IssuesList: () => null }));

import Issues from "./page";

describe("Issues deployment availability", () => {
  beforeEach(() => {
    getAllProviders.mockResolvedValue({ data: [] });
    getAllProviderGroups.mockResolvedValue({ data: [] });
  });
  it("returns not found before loading data in Local Server", async () => {
    vi.stubEnv("UI_CLOUD_ENABLED", "false");
    await expect(Issues({ searchParams: Promise.resolve({}) })).rejects.toThrow(
      "NOT_FOUND",
    );
    expect(getAllProviders).not.toHaveBeenCalled();
    expect(getAllProviderGroups).not.toHaveBeenCalled();
  });
  it("loads the scope controls in Cloud deployments", async () => {
    vi.stubEnv("UI_CLOUD_ENABLED", "true");
    await Issues({ searchParams: Promise.resolve({}) });
    expect(notFound).not.toHaveBeenCalled();
    expect(getAllProviders).toHaveBeenCalledOnce();
    expect(getAllProviderGroups).toHaveBeenCalledOnce();
  });
});
