import { render, waitFor } from "@testing-library/react";
import { beforeEach, describe, expect, it, vi } from "vitest";

import type { Requirement } from "@/types/compliance";

import { ClientAccordionContent } from "./client-accordion-content";

const { getFindingsMock, getLatestFindingsMock } = vi.hoisted(() => ({
  getFindingsMock: vi.fn(),
  getLatestFindingsMock: vi.fn(),
}));

let currentSearchParams = new URLSearchParams();

vi.mock("next/navigation", () => ({
  useSearchParams: () => currentSearchParams,
}));

vi.mock("@/actions/findings/findings", () => ({
  getFindings: getFindingsMock,
  getLatestFindings: getLatestFindingsMock,
}));

vi.mock("@/components/findings/table", () => ({
  getStandaloneFindingColumns: () => [],
  SkeletonTableFindings: () => <div data-testid="skeleton" />,
}));

vi.mock("@/components/ui/accordion/Accordion", () => ({
  Accordion: () => <div data-testid="accordion" />,
}));

vi.mock("@/components/ui/table", () => ({
  DataTable: () => <div data-testid="data-table" />,
}));

vi.mock("@/lib/compliance/compliance-mapper", () => ({
  getComplianceMapper: () => ({ getDetailsComponent: () => null }),
}));

vi.mock("@/lib", () => ({
  createDict: () => ({}),
  FINDINGS_DEFAULT_SORT: "severity",
  MUTED_FILTER: { EXCLUDE: "false" },
}));

const requirement = {
  check_ids: ["check-1"],
  status: "FAIL",
} as unknown as Requirement;

describe("ClientAccordionContent findings drill-down", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    getFindingsMock.mockResolvedValue({ data: [], meta: {} });
    getLatestFindingsMock.mockResolvedValue({ data: [], meta: {} });
  });

  describe("when provider filters drive aggregated mode", () => {
    it("loads findings from the latest endpoint, not the scan-scoped one", async () => {
      // Given - the URL carries a provider-scope filter and no scanId
      currentSearchParams = new URLSearchParams({
        complianceId: "cis_2.0_aws",
        "filter[provider_type__in]": "aws",
      });

      // When
      render(
        <ClientAccordionContent
          requirement={requirement}
          framework="cis_aws"
          scanId=""
        />,
      );

      // Then - /findings 400s without a scan or date filter, so aggregated mode
      // must use /findings/latest, forwarding the provider filters and no scan
      await waitFor(() =>
        expect(getLatestFindingsMock).toHaveBeenCalledTimes(1),
      );
      expect(getFindingsMock).not.toHaveBeenCalled();
      const { filters } = getLatestFindingsMock.mock.calls[0][0];
      expect(filters).toMatchObject({ "filter[provider_type__in]": "aws" });
      expect(filters).not.toHaveProperty("filter[scan]");
    });
  });

  describe("when a single scan drives the scope", () => {
    it("loads findings from the scan-scoped endpoint", async () => {
      // Given - no provider filters, a concrete scanId
      currentSearchParams = new URLSearchParams({
        complianceId: "cis_2.0_aws",
      });

      // When
      render(
        <ClientAccordionContent
          requirement={requirement}
          framework="cis_aws"
          scanId="scan-1"
        />,
      );

      // Then
      await waitFor(() => expect(getFindingsMock).toHaveBeenCalledTimes(1));
      expect(getLatestFindingsMock).not.toHaveBeenCalled();
      const { filters } = getFindingsMock.mock.calls[0][0];
      expect(filters).toMatchObject({ "filter[scan]": "scan-1" });
    });
  });
});
