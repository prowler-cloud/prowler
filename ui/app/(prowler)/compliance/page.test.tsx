import { readFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { render, screen } from "@testing-library/react";
import {
  Children,
  isValidElement,
  Suspense,
  type ReactElement,
  type ReactNode,
} from "react";
import { beforeEach, describe, expect, it, vi } from "vitest";

import Compliance from "./page";

const {
  complianceOverviewGridSpy,
  getComplianceOverviewMetadataInfoMock,
  getCompliancesOverviewMock,
  getScansMock,
  getThreatScoreMock,
  loadComplianceWatchlistContextMock,
} = vi.hoisted(() => ({
  complianceOverviewGridSpy: vi.fn(),
  getComplianceOverviewMetadataInfoMock: vi.fn(),
  getCompliancesOverviewMock: vi.fn(),
  getScansMock: vi.fn(),
  getThreatScoreMock: vi.fn(),
  loadComplianceWatchlistContextMock: vi.fn(),
}));

vi.mock("@/actions/compliances", () => ({
  COMPLIANCE_OVERVIEW_RESOURCE_TYPE: { TASK: "tasks" },
  getComplianceOverviewMetadataInfo: getComplianceOverviewMetadataInfoMock,
  getCompliancesOverview: getCompliancesOverviewMock,
}));

vi.mock("@/actions/overview", () => ({
  getThreatScore: getThreatScoreMock,
}));

vi.mock("@/actions/scans", () => ({
  getScans: getScansMock,
  getScansByState: vi.fn(),
}));

vi.mock("@/lib/shared/env", () => ({
  isCloud: () => false,
}));

vi.mock("./_lib/watchlist-context", () => ({
  loadComplianceWatchlistContext: loadComplianceWatchlistContextMock,
}));

vi.mock("@/components/shadcn/content-layout", () => ({
  ContentLayout: ({ children }: { children: ReactNode }) => <>{children}</>,
}));

vi.mock("./_components/compliance-page-tabs", () => ({
  CompliancePageTabs: ({ perScanContent }: { perScanContent: ReactNode }) => (
    <>{perScanContent}</>
  ),
}));

vi.mock("./_components/cross-account-overview-section", () => ({
  CrossAccountOverviewSection: () => <div>Cross-account overview</div>,
}));

vi.mock("./_components/cross-provider-overview", () => ({
  CrossProviderOverview: () => <div>Cross-provider overview</div>,
}));

vi.mock("./_components/multiple-scans-skeleton", () => ({
  CrossAccountOverviewSkeleton: () => <div>Cross-account loading</div>,
  CrossProviderOverviewSkeleton: () => <div>Cross-provider loading</div>,
}));

vi.mock("@/components/compliance", () => ({
  ComplianceSkeletonGrid: () => <div>Loading compliance data</div>,
  NoScansAvailable: () => <div>No scans available</div>,
  ThreatScoreBadge: () => <div>Threat score</div>,
}));

vi.mock("@/components/compliance/compliance-header/compliance-filters", () => ({
  ComplianceFilters: () => <div>Compliance filters</div>,
}));

vi.mock("@/components/compliance/compliance-overview-grid", () => ({
  ComplianceOverviewGrid: (props: { frameworks: Array<{ id: string }> }) => {
    complianceOverviewGridSpy(props);
    return <div>Compliance overview grid</div>;
  },
}));

vi.mock("@/components/compliance/watchlist/watchlist-controls", () => ({
  WatchlistControls: () => <div>Watchlist controls</div>,
}));

interface ComplianceTabsTestProps {
  perScanContent: ReactElement<{ children: ReactNode }>;
}

interface ContentLayoutTestProps {
  children: ReactElement<ComplianceTabsTestProps>;
}

type AsyncServerComponent = (
  props: Record<string, unknown>,
) => Promise<ReactNode>;

const renderPerScanGrid = async () => {
  const page = (await Compliance({
    searchParams: Promise.resolve({ scanId: "scan-1" }),
  })) as ReactElement<ContentLayoutTestProps>;
  const perScanContent = page.props.children.props.perScanContent;
  const suspense = Children.toArray(perScanContent.props.children).find(
    (child) => isValidElement(child) && child.type === Suspense,
  );

  if (!isValidElement<{ children: ReactElement }>(suspense)) {
    throw new Error("Expected the per-scan compliance Suspense boundary");
  }

  const grid = suspense.props.children as ReactElement<
    Record<string, unknown>,
    AsyncServerComponent
  >;
  render(await grid.type(grid.props));
};

describe("Compliance overview page", () => {
  const currentDir = path.dirname(fileURLToPath(import.meta.url));
  const filePath = path.join(currentDir, "page.tsx");
  const source = readFileSync(filePath, "utf8");

  it("delegates client-side search to ComplianceOverviewGrid", () => {
    expect(source).toContain("ComplianceOverviewGrid");
    expect(source).not.toContain("filter[search]");
  });

  it("uses layout-matched skeletons for the Multiple Scans islands", () => {
    expect(source).toContain("<CrossProviderOverviewSkeleton />");
    expect(source).toContain("<CrossAccountOverviewSkeleton />");
  });
});

describe("Compliance overview task response", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    getScansMock.mockResolvedValue({
      data: [
        {
          id: "scan-1",
          attributes: {
            name: "Production scan",
            completed_at: "2026-08-05T17:00:00Z",
          },
          relationships: {
            provider: { data: { id: "provider-1" } },
          },
        },
      ],
      included: [
        {
          id: "provider-1",
          type: "providers",
          attributes: {
            provider: "aws",
            uid: "123456789012",
            alias: "Production",
          },
        },
      ],
    });
    getComplianceOverviewMetadataInfoMock.mockResolvedValue({
      data: { attributes: { regions: [] } },
    });
    getThreatScoreMock.mockResolvedValue({ data: [] });
    loadComplianceWatchlistContextMock.mockResolvedValue({
      entries: [],
      canManage: false,
    });
  });

  it("shows a pending state while compliance data is being generated", async () => {
    // Given - API returned the JSON:API task resource from its HTTP 202 response
    getCompliancesOverviewMock.mockResolvedValue({
      data: {
        id: "task-1",
        type: "tasks",
        attributes: { state: "executing" },
      },
    });

    // When - the server-rendered compliance page handles the response
    await renderPerScanGrid();

    // Then - the request remains renderable instead of throwing on data.filter
    expect(
      await screen.findByText(
        "Compliance data is still being generated. Please try again shortly.",
      ),
    ).toBeInTheDocument();
  });

  it("renders framework arrays after removing ThreatScore", async () => {
    // Given - API returned its normal compliance overview collection
    getCompliancesOverviewMock.mockResolvedValue({
      data: [
        {
          id: "prowler_threatscore_aws",
          type: "compliance-overviews",
          attributes: { framework: "ProwlerThreatScore" },
        },
        {
          id: "cis_1.5_aws",
          type: "compliance-overviews",
          attributes: { framework: "CIS", version: "1.5" },
        },
      ],
    });

    // When - the server-rendered compliance grid handles the collection
    await renderPerScanGrid();

    // Then - normal rendering remains unchanged
    expect(screen.getByText("Compliance overview grid")).toBeInTheDocument();
    expect(complianceOverviewGridSpy).toHaveBeenCalledWith(
      expect.objectContaining({
        frameworks: [expect.objectContaining({ id: "cis_1.5_aws" })],
      }),
    );
  });

  it("shows the invalid scan message for a JSON:API error response", async () => {
    // Given - handleApiResponse converted a client error to its error result
    getCompliancesOverviewMock.mockResolvedValue({
      error: "Invalid scan ID.",
      errors: [{ detail: "Invalid scan ID." }],
      status: 400,
    });

    // When - the server-rendered compliance grid handles the error
    await renderPerScanGrid();

    // Then - the intended error state is reachable
    expect(screen.getByText("Provide a valid scan ID.")).toBeInTheDocument();
  });
});
