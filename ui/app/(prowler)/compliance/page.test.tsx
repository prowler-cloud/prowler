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
  complianceFiltersSpy,
  complianceOverviewGridSpy,
  getComplianceOverviewMetadataInfoMock,
  getCompliancesOverviewMock,
  getScanMock,
  getScansMock,
  getThreatScoreMock,
  isCloudMock,
  loadComplianceWatchlistContextMock,
} = vi.hoisted(() => ({
  complianceFiltersSpy: vi.fn(),
  complianceOverviewGridSpy: vi.fn(),
  getComplianceOverviewMetadataInfoMock: vi.fn(),
  getCompliancesOverviewMock: vi.fn(),
  getScanMock: vi.fn(),
  getScansMock: vi.fn(),
  getThreatScoreMock: vi.fn(),
  isCloudMock: vi.fn(() => false),
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
  getScan: getScanMock,
  getScans: getScansMock,
  getScansByState: vi.fn(),
}));

vi.mock("@/lib/shared/env", () => ({
  isCloud: isCloudMock,
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
  ComplianceFilters: (props: { scans: Array<{ id: string }> }) => {
    complianceFiltersSpy(props);
    return <div>Compliance filters</div>;
  },
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
    isCloudMock.mockReturnValue(false);
    getScanMock.mockResolvedValue(undefined);
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

  it("keeps partial scans out of the per-scan selector", async () => {
    // Given - a Cloud partial scan among the completed scans; it computes no
    // compliance, so selecting it would show nothing and its downloads fail
    isCloudMock.mockReturnValue(true);
    getScansMock.mockResolvedValue({
      data: [
        {
          id: "scan-1",
          attributes: {
            name: "Production scan",
            completed_at: "2026-08-05T17:00:00Z",
          },
          relationships: { provider: { data: { id: "provider-1" } } },
        },
        {
          id: "scan-partial",
          attributes: {
            name: "Re-check",
            completed_at: "2026-08-06T09:00:00Z",
            is_partial: true,
          },
          relationships: { provider: { data: { id: "provider-1" } } },
        },
      ],
      included: [
        {
          type: "providers",
          id: "provider-1",
          attributes: { provider: "aws", uid: "123456789012", alias: "prod" },
        },
      ],
    });
    getCompliancesOverviewMock.mockResolvedValue({ data: [] });

    // When
    const page = await Compliance({
      searchParams: Promise.resolve({ scanId: "scan-1" }),
    });
    render(page as ReactElement);

    // Then - only the full scan reaches the selector, and the API is asked
    // for the flag that tells them apart
    expect(complianceFiltersSpy).toHaveBeenCalledWith(
      expect.objectContaining({
        scans: [expect.objectContaining({ id: "scan-1" })],
      }),
    );
    expect(getScansMock).toHaveBeenCalledWith(
      expect.objectContaining({
        // Filtered at the API too, so a page full of re-checks cannot hide
        // the full scans behind it.
        filters: expect.objectContaining({ "filter[is_partial]": "false" }),
        fields: { scans: "name,completed_at,provider,is_partial" },
      }),
    );
  });

  it("does not send the Cloud-only partial filter outside Prowler Cloud", async () => {
    getCompliancesOverviewMock.mockResolvedValue({ data: [] });

    await Compliance({ searchParams: Promise.resolve({ scanId: "scan-1" }) });

    expect(getScansMock).toHaveBeenCalledWith(
      expect.objectContaining({
        filters: { "filter[state]": "completed" },
      }),
    );
  });

  it("falls back to the first full scan when the URL names a partial scan", async () => {
    // Given - a stale link to a partial scan, absent from the eligible list
    getScanMock.mockResolvedValue({
      data: { id: "scan-partial", attributes: { is_partial: true } },
    });
    getCompliancesOverviewMock.mockResolvedValue({ data: [] });

    // When
    const page = await Compliance({
      searchParams: Promise.resolve({ scanId: "scan-partial" }),
    });
    render(page as ReactElement);

    // Then - the page selects a scan that has compliance instead
    expect(getScanMock).toHaveBeenCalledWith("scan-partial");
    expect(complianceFiltersSpy).toHaveBeenCalledWith(
      expect.objectContaining({ selectedScanId: "scan-1" }),
    );
    expect(getCompliancesOverviewMock).toHaveBeenCalledWith(
      expect.objectContaining({ scanId: "scan-1" }),
    );
  });

  it("keeps trusting a URL scan id that is older than the listed page", async () => {
    // Given - a full scan beyond the first page: not listed, not partial
    getScanMock.mockResolvedValue({
      data: { id: "scan-old", attributes: { is_partial: false } },
    });
    getCompliancesOverviewMock.mockResolvedValue({ data: [] });

    // When
    const page = await Compliance({
      searchParams: Promise.resolve({ scanId: "scan-old" }),
    });
    render(page as ReactElement);

    // Then
    expect(complianceFiltersSpy).toHaveBeenCalledWith(
      expect.objectContaining({ selectedScanId: "scan-old" }),
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
