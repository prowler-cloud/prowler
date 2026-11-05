import { render, screen } from "@testing-library/react";
import { beforeEach, describe, expect, it, vi } from "vitest";

const {
  getAllProviderGroupsMock,
  getAllProvidersMock,
  getCrossAccountComplianceOverviewMock,
  getLatestCrossAccountPdfMock,
} = vi.hoisted(() => ({
  getAllProviderGroupsMock: vi.fn(),
  getAllProvidersMock: vi.fn(),
  getCrossAccountComplianceOverviewMock: vi.fn(),
  getLatestCrossAccountPdfMock: vi.fn(),
}));

vi.mock("@/actions/manage-groups/manage-groups", () => ({
  getAllProviderGroups: getAllProviderGroupsMock,
}));

vi.mock("@/actions/providers", () => ({
  getAllProviders: getAllProvidersMock,
}));

vi.mock("@/components/icons/compliance/IconCompliance", () => ({
  getComplianceIcon: () => undefined,
}));

vi.mock("@/components/icons/providers-badge/provider-type-icon", () => ({
  ProviderTypeIcon: () => null,
}));

vi.mock("@/components/lighthouse/context-contributor", () => ({
  LighthouseContextContributor: ({ item }: { item: unknown }) => (
    <output data-testid="lighthouse-context">{JSON.stringify(item)}</output>
  ),
}));

vi.mock("@/lib/compliance/compliance-mapper", () => ({
  getComplianceMapper: () => ({
    mapComplianceData: () => [],
    getTopFailedSections: () => ({
      items: [],
      type: "requirements",
      prepopulated: false,
    }),
  }),
}));

vi.mock("../_actions/cross-account", () => ({
  getCrossAccountComplianceOverview: getCrossAccountComplianceOverviewMock,
  getLatestCrossAccountPdf: getLatestCrossAccountPdfMock,
}));

vi.mock("../_lib/aggregated-compliance-detail", () => ({
  getAggregatedInitialExpandedKeys: () => [],
  getAggregatedRequirementsTotals: () => ({
    pass: 8,
    fail: 2,
    manual: 1,
  }),
}));

vi.mock("../_lib/cross-account-accordion", () => ({
  toCrossAccountAccordionItems: () => [],
}));

vi.mock("../_lib/cross-account-adapter", () => ({
  buildAccountExtrasMap: () => new Map(),
  computeAccountBreakdown: () => [],
  crossAccountToMapperInput: () => ({
    attributesData: {},
    requirementsData: {},
  }),
}));

vi.mock("../_lib/cross-account-frameworks", () => ({
  parseCrossAccountFilters: () => ({}),
}));

vi.mock("./aggregated-compliance-detail", () => ({
  AggregatedComplianceDetail: () => (
    <div data-testid="aggregated-compliance-detail" />
  ),
}));

vi.mock("./cross-provider-error-alert", () => ({
  CrossProviderErrorAlert: () => <div data-testid="cross-provider-error" />,
}));

vi.mock("./cross-provider-filters", () => ({
  CrossProviderFilters: () => <div data-testid="cross-provider-filters" />,
}));

vi.mock("./cross-provider-pdf-button", () => ({
  CrossProviderPdfButton: () => <div data-testid="cross-provider-pdf" />,
}));

vi.mock("./provider-coverage-card", () => ({
  ProviderCoverageCard: () => <div data-testid="provider-coverage" />,
}));

import { CrossAccountDetail } from "./cross-account-detail";

describe("CrossAccountDetail", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    getAllProvidersMock.mockResolvedValue({ data: [] });
    getAllProviderGroupsMock.mockResolvedValue({ data: [] });
    getLatestCrossAccountPdfMock.mockResolvedValue(null);
    getCrossAccountComplianceOverviewMock.mockResolvedValue({
      status: "success",
      response: {
        data: {
          attributes: {
            accounts: [],
            framework: "CIS",
            name: "CIS AWS Foundations",
            scan_ids: ["scan-1"],
            version: "2.0",
          },
        },
      },
    });
  });

  it("publishes cross-account compliance context", async () => {
    // Given / When
    render(
      await CrossAccountDetail({
        compliancetitle: "cis-aws-foundations",
        complianceId: "cis_aws_2.0",
        providerType: "aws",
        searchParams: {},
        targetSection: "IAM",
      }),
    );

    // Then
    expect(screen.getByTestId("aggregated-compliance-detail")).toBeVisible();
    expect(screen.getByTestId("lighthouse-context")).toHaveTextContent(
      '"mode":"cross-account"',
    );
    expect(screen.getByTestId("lighthouse-context")).toHaveTextContent(
      '"section":"IAM"',
    );
    expect(screen.getByTestId("lighthouse-context")).toHaveTextContent(
      '"totals":{"passed":8,"failed":2,"total":11}',
    );
  });
});
