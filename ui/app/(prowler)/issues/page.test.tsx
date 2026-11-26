import { render, screen } from "@testing-library/react";
import { beforeEach, describe, expect, it, vi } from "vitest";

const {
  getAllProviders,
  getAllProviderGroups,
  getSamplePreviewState,
  notFound,
} = vi.hoisted(() => ({
  getAllProviders: vi.fn(),
  getAllProviderGroups: vi.fn(),
  getSamplePreviewState: vi.fn(),
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
  ContentLayout: ({ children }: { children: React.ReactNode }) => (
    <>{children}</>
  ),
}));
vi.mock("@/components/shared/premium-preview-page", () => ({
  PremiumPreviewPage: () => <section data-testid="premium-preview" />,
}));
vi.mock("./_components/issues-list", () => ({ IssuesList: () => null }));
vi.mock("./_components/issues-preview-hook", () => ({
  IssuesPreviewHook: () => null,
  IssuesPreviewHookSkeleton: () => null,
}));
vi.mock("@/components/shared/sample-preview/sample-preview-banner", () => ({
  SamplePreviewBanner: () => null,
}));
vi.mock("@/lib/sample-preview/get-sample-preview-state", () => ({
  getSamplePreviewState,
}));

import Issues from "./page";

describe("Issues deployment availability", () => {
  beforeEach(() => {
    getAllProviders.mockResolvedValue({ data: [] });
    getAllProviderGroups.mockResolvedValue({ data: [] });
    getSamplePreviewState.mockResolvedValue({ active: false });
  });
  it("renders the premium preview without Cloud data in Local Server", async () => {
    // Given
    vi.stubEnv("UI_CLOUD_ENABLED", "false");

    // When
    render(await Issues({ searchParams: Promise.resolve({}) }));

    // Then
    expect(screen.getByTestId("premium-preview")).toBeInTheDocument();
    expect(getAllProviders).not.toHaveBeenCalled();
    expect(getAllProviderGroups).not.toHaveBeenCalled();
    expect(getSamplePreviewState).not.toHaveBeenCalled();
  });
  it("loads the scope controls in Cloud deployments", async () => {
    vi.stubEnv("UI_CLOUD_ENABLED", "true");
    await Issues({ searchParams: Promise.resolve({}) });
    expect(notFound).not.toHaveBeenCalled();
    expect(getAllProviders).toHaveBeenCalledOnce();
    expect(getAllProviderGroups).toHaveBeenCalledOnce();
  });
  it("skips the scope controls' data while the sample is shown", async () => {
    vi.stubEnv("UI_CLOUD_ENABLED", "true");
    getSamplePreviewState.mockResolvedValue({
      active: true,
      stage: "no_provider",
      runningScan: null,
    });
    await Issues({ searchParams: Promise.resolve({}) });
    expect(getAllProviders).not.toHaveBeenCalled();
    expect(getAllProviderGroups).not.toHaveBeenCalled();
  });
});
