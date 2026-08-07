import { render, screen } from "@testing-library/react";
import {
  Children,
  isValidElement,
  Suspense,
  type ReactElement,
  type ReactNode,
} from "react";
import { beforeEach, describe, expect, it, vi } from "vitest";

import ComplianceDetail from "./page";

const {
  getComplianceAttributesMock,
  getComplianceOverviewMetadataInfoMock,
  getComplianceRequirementsMock,
  getScanMock,
  mapComplianceDataMock,
} = vi.hoisted(() => ({
  getComplianceAttributesMock: vi.fn(),
  getComplianceOverviewMetadataInfoMock: vi.fn(),
  getComplianceRequirementsMock: vi.fn(),
  getScanMock: vi.fn(),
  mapComplianceDataMock: vi.fn(),
}));

vi.mock("next/navigation", () => ({
  notFound: vi.fn(() => {
    throw new Error("notFound");
  }),
  redirect: vi.fn(() => {
    throw new Error("redirect");
  }),
}));

vi.mock("@/actions/compliances", () => ({
  COMPLIANCE_OVERVIEW_RESOURCE_TYPE: { TASK: "tasks" },
  getComplianceAttributes: getComplianceAttributesMock,
  getComplianceOverviewMetadataInfo: getComplianceOverviewMetadataInfoMock,
  getComplianceRequirements: getComplianceRequirementsMock,
  getCompliancesOverview: vi.fn(),
}));

vi.mock("@/actions/overview", () => ({
  getThreatScore: vi.fn(),
}));

vi.mock("@/actions/scans", () => ({
  getScan: getScanMock,
}));

vi.mock("@/components/compliance", () => ({
  ClientAccordionWrapper: () => <div>Empty requirements</div>,
  ComplianceDownloadContainer: () => null,
  ComplianceHeader: () => null,
  ComplianceWarming: () => null,
  RequirementsStatusCard: ({
    pass,
    fail,
    manual,
  }: {
    pass: number;
    fail: number;
    manual: number;
  }) => (
    <div>
      Requirements: {pass} pass, {fail} fail, {manual} manual
    </div>
  ),
  RequirementsStatusCardSkeleton: () => null,
  SkeletonAccordion: () => null,
  ThreatScoreBreakdownCard: () => null,
  ThreatScoreBreakdownCardSkeleton: () => null,
  TopFailedSectionsCard: () => null,
  TopFailedSectionsCardSkeleton: () => null,
}));

vi.mock("@/components/icons/compliance/IconCompliance", () => ({
  getComplianceIcon: vi.fn(),
}));

vi.mock("@/components/lighthouse/context-contributor", () => ({
  LighthouseContextContributor: () => null,
}));

vi.mock("@/components/shadcn/button/button", () => ({
  Button: ({ children }: { children: ReactNode }) => <>{children}</>,
}));

vi.mock("@/components/shadcn/card/card", () => ({
  Card: ({ children }: { children: ReactNode }) => <>{children}</>,
}));

vi.mock("@/components/shadcn/content-layout", () => ({
  ContentLayout: ({ children }: { children: ReactNode }) => <>{children}</>,
}));

vi.mock("@/lib/compliance/compliance-mapper", () => ({
  getComplianceMapper: () => ({
    getTopFailedSections: vi.fn(() => []),
    mapComplianceData: mapComplianceDataMock,
    toAccordionItems: vi.fn(() => []),
  }),
}));

vi.mock("@/lib/compliance/compliance-report-types", () => ({
  getReportTypeForCompliance: vi.fn(),
  pickLatestCisPerProvider: vi.fn(() => new Set()),
}));

vi.mock("@/lib/shared/env", () => ({
  isCloud: () => false,
}));

vi.mock("../_components/cross-account-detail", () => ({
  CrossAccountDetail: () => null,
}));

vi.mock("../_components/cross-provider-detail", () => ({
  CrossProviderDetail: () => null,
}));

vi.mock("../_lib/cross-provider-frameworks", () => ({
  resolveCrossProviderFramework: vi.fn(),
}));

vi.mock("../_lib/search-params-key", () => ({
  buildSearchParamsKey: vi.fn(() => "search-params"),
}));

interface ContentLayoutTestProps {
  children: ReactNode;
}

type AsyncServerComponent = (
  props: Record<string, unknown>,
) => Promise<ReactNode>;

const renderPerScanContent = async () => {
  const page = (await ComplianceDetail({
    params: Promise.resolve({ compliancetitle: "ISO 27001" }),
    searchParams: Promise.resolve({
      complianceId: "iso27001_2022_aws",
      scanId: "scan-1",
    }),
  })) as ReactElement<ContentLayoutTestProps>;
  const suspense = Children.toArray(page.props.children).find(
    (child) => isValidElement(child) && child.type === Suspense,
  );

  if (!isValidElement<{ children: ReactElement }>(suspense)) {
    throw new Error("Expected the per-scan compliance Suspense boundary");
  }

  const content = suspense.props.children as ReactElement<
    Record<string, unknown>,
    AsyncServerComponent
  >;
  render(await content.type(content.props));
};

describe("Compliance detail task response", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    getComplianceOverviewMetadataInfoMock.mockResolvedValue({
      data: { attributes: { regions: [] } },
    });
    getComplianceAttributesMock.mockResolvedValue({
      data: [
        {
          id: "iso27001_2022_aws",
          type: "compliance-overview-attributes",
          attributes: {
            compliance_name: "ISO 27001",
            framework: "ISO27001",
          },
        },
      ],
    });
    getScanMock.mockResolvedValue(undefined);
    mapComplianceDataMock.mockImplementation(
      (_attributesData, requirementsData) => {
        const requirements = requirementsData.data;
        requirements.forEach(() => undefined);
        return [];
      },
    );
  });

  it("renders an empty detail while requirements are being generated", async () => {
    // Given - the requirements endpoint returned a JSON:API task resource
    getComplianceRequirementsMock.mockResolvedValue({
      data: {
        id: "task-1",
        type: "tasks",
        attributes: { state: "executing" },
      },
    });

    // When - the server-rendered detail handles the pending response
    await renderPerScanContent();

    // Then - the task never reaches the requirements array mapper
    expect(
      screen.getByText("Requirements: 0 pass, 0 fail, 0 manual"),
    ).toBeInTheDocument();
  });

  it("maps a completed requirements collection", async () => {
    // Given - the requirements endpoint returned its normal collection
    getComplianceRequirementsMock.mockResolvedValue({
      data: [
        {
          id: "requirement-1",
          type: "compliance-overview-requirements",
          attributes: { status: "PASS" },
        },
      ],
    });
    mapComplianceDataMock.mockReturnValue([
      {
        name: "ISO 27001",
        pass: 1,
        fail: 0,
        manual: 0,
      },
    ]);

    // When - the server-rendered detail handles the completed response
    await renderPerScanContent();

    // Then - normal mapper output is still rendered
    expect(
      screen.getByText("Requirements: 1 pass, 0 fail, 0 manual"),
    ).toBeInTheDocument();
  });
});
