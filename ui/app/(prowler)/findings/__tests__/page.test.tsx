import { render, screen } from "@testing-library/react";
import type { ComponentProps, ReactNode } from "react";
import { beforeEach, describe, expect, it, vi } from "vitest";

import Findings from "../page";

vi.mock("@/actions/finding-groups", () => ({
  adaptFindingGroupsResponse: vi.fn(() => []),
  getFindingGroups: vi.fn(),
  getLatestFindingGroups: vi.fn(() => ({ data: [], errors: [], meta: {} })),
}));

vi.mock("@/actions/findings", () => ({
  getLatestMetadataInfo: vi.fn(() => ({
    data: {
      attributes: {
        categories: [],
        groups: [],
        regions: [],
        resource_types: [],
        services: [],
      },
    },
  })),
  getMetadataInfo: vi.fn(),
}));

vi.mock("@/actions/providers", () => ({
  getProviders: vi.fn(() => ({ data: [] })),
}));

vi.mock("@/actions/scans", () => ({
  getScan: vi.fn(),
  getScans: vi.fn(() => ({ data: [] })),
}));

vi.mock("@/app/(prowler)/alerts/_components", () => ({
  SeedFromFindingsButton: () => <button>Create Alert</button>,
}));

vi.mock("@/components/findings/findings-filters", () => ({
  FindingsFilters: ({ trailingControls }: { trailingControls?: ReactNode }) => (
    <section aria-label="Findings filters">
      <span>Findings filters</span>
      {trailingControls}
    </section>
  ),
}));

vi.mock("@/components/findings/table", () => ({
  FindingsGroupTable: () => <div>Findings table</div>,
  SkeletonTableFindings: () => <div>Loading findings</div>,
}));

vi.mock("@/components/ui", () => ({
  ContentLayout: ({ children }: ComponentProps<"main">) => (
    <main>{children}</main>
  ),
}));

vi.mock("@/contexts", () => ({
  FilterTransitionWrapper: ({ children }: { children: ReactNode }) => (
    <>{children}</>
  ),
}));

vi.mock("@/lib", () => ({
  applyDefaultMutedFilter: vi.fn((filters: Record<string, string>) => filters),
  createScanDetailsMapping: vi.fn(() => []),
  extractFiltersAndQuery: vi.fn(() => ({ filters: {}, query: "" })),
  extractSortAndKey: vi.fn(() => ({ encodedSort: undefined })),
  hasDateOrScanFilter: vi.fn(() => false),
}));

vi.mock("@/lib/findings-scan-filters", () => ({
  resolveFindingScanDateFilters: vi.fn(({ filters }) => filters),
}));

describe("Findings page alerts controls", () => {
  beforeEach(() => {
    delete process.env.NEXT_PUBLIC_IS_CLOUD_ENV;
  });

  it("should hide the create alert control when Cloud is disabled", async () => {
    // Given / When
    render(await Findings({ searchParams: Promise.resolve({}) }));

    // Then
    expect(
      screen.queryByRole("button", { name: /create alert/i }),
    ).not.toBeInTheDocument();
  });

  it("should render the create alert control when Cloud is enabled", async () => {
    // Given
    process.env.NEXT_PUBLIC_IS_CLOUD_ENV = "true";

    // When
    render(await Findings({ searchParams: Promise.resolve({}) }));

    // Then
    expect(screen.getByRole("button", { name: /create alert/i })).toBeVisible();
  });
});
