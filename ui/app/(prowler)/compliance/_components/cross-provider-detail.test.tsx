import { render, screen } from "@testing-library/react";
import type { ReactNode } from "react";
import { beforeEach, describe, expect, it, vi } from "vitest";

import { getAllProviderGroups } from "@/actions/manage-groups/manage-groups";
import { getAllProviders } from "@/actions/providers";
import { getComplianceIcon } from "@/components/icons/compliance/IconCompliance";

import {
  getCrossProviderComplianceOverview,
  getLatestCrossProviderPdf,
} from "../_actions/cross-provider";
import { CROSS_PROVIDER_OVERVIEW_RESULT_STATUS } from "../_types";

import { CrossProviderDetail } from "./cross-provider-detail";

vi.mock("@/actions/manage-groups/manage-groups", () => ({
  getAllProviderGroups: vi.fn(),
}));

vi.mock("@/actions/providers", () => ({
  getAllProviders: vi.fn(),
}));

vi.mock("@/components/icons/compliance/IconCompliance", () => ({
  getComplianceIcon: vi.fn(() => "/compliance.svg"),
}));

vi.mock("@/components/lighthouse/context-contributor", () => ({
  LighthouseContextContributor: () => null,
}));

vi.mock("@/components/shadcn/content-layout", () => ({
  ContentLayout: ({
    title,
    children,
  }: {
    title: string;
    children: ReactNode;
  }) => (
    <div data-testid="content-layout" data-title={title}>
      {children}
    </div>
  ),
}));

vi.mock("@/lib/compliance/compliance-mapper", () => ({
  getComplianceMapper: () => ({
    getTopFailedSections: () => ({
      items: [],
      type: "section",
      prepopulated: false,
    }),
    mapComplianceData: () => [],
  }),
}));

vi.mock("../_actions/cross-provider", () => ({
  getCrossProviderComplianceOverview: vi.fn(),
  getLatestCrossProviderPdf: vi.fn(),
}));

vi.mock("../_lib/aggregated-compliance-detail", () => ({
  getAggregatedInitialExpandedKeys: () => [],
  getAggregatedRequirementsTotals: () => ({ pass: 0, fail: 0, manual: 0 }),
}));

vi.mock("../_lib/cross-provider-accordion", () => ({
  toCrossProviderAccordionItems: () => [],
}));

vi.mock("../_lib/cross-provider-adapter", () => ({
  buildRequirementExtrasMap: () => new Map(),
  computeProviderBreakdown: () => [],
  crossProviderToMapperInput: () => ({
    attributesData: {},
    requirementsData: {},
  }),
}));

vi.mock("./aggregated-compliance-detail", () => ({
  AggregatedComplianceDetail: ({
    compliancetitle,
  }: {
    compliancetitle: string;
  }) => (
    <div data-testid="aggregated-compliance" data-title={compliancetitle} />
  ),
}));

vi.mock("./cross-provider-filters", () => ({
  CrossProviderFilters: () => null,
}));

vi.mock("./cross-provider-hub-link", () => ({
  CrossProviderHubLink: () => null,
}));

vi.mock("./cross-provider-pdf-button", () => ({
  CrossProviderPdfButton: () => null,
}));

vi.mock("./provider-coverage-card", () => ({
  ProviderCoverageCard: () => null,
}));

describe("CrossProviderDetail", () => {
  beforeEach(() => {
    vi.mocked(getAllProviders).mockResolvedValue({
      data: [],
      links: { first: "", last: "", next: null, prev: null },
      meta: { pagination: { page: 1, pages: 1, count: 0 }, version: "" },
    });
    vi.mocked(getAllProviderGroups).mockResolvedValue({
      data: [],
      links: { first: "", last: "", next: null, prev: null },
      meta: { pagination: { page: 1, pages: 1, count: 0 }, version: "" },
    });
    vi.mocked(getLatestCrossProviderPdf).mockResolvedValue(null);
    vi.mocked(getCrossProviderComplianceOverview).mockResolvedValue({
      status: CROSS_PROVIDER_OVERVIEW_RESULT_STATUS.SUCCESS,
      response: {
        data: {
          type: "cross-provider-compliance-overviews",
          id: "acme_1.0",
          attributes: {
            compliance_id: "acme_1.0",
            framework: "ACME",
            name: "ACME Framework",
            version: "1.0",
            description: "External framework",
            compatible_providers: ["aws"],
            requested_providers: ["aws"],
            providers: ["aws"],
            scan_ids: [],
            scan_ids_by_provider: {},
            requirements_passed: 0,
            requirements_failed: 0,
            requirements_manual: 0,
            total_requirements: 0,
            requirements: [],
          },
        },
      },
    });
  });

  it("uses API identity instead of route-controlled title and version", async () => {
    // Given - a valid framework id with spoofed route metadata
    const props = {
      compliancetitle: "Spoofed-Framework",
      complianceId: "acme_1.0",
      searchParams: { version: "999.0" },
    };

    // When - the server detail renders the API result
    render(await CrossProviderDetail(props));

    // Then - every visible identity comes from the validated overview
    expect(screen.getByTestId("content-layout")).toHaveAttribute(
      "data-title",
      "ACME - 1.0",
    );
    expect(getComplianceIcon).toHaveBeenCalledWith("ACME");
    expect(screen.getByTestId("aggregated-compliance")).toHaveAttribute(
      "data-title",
      "ACME",
    );
  });
});
