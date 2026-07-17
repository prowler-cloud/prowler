import { render, screen } from "@testing-library/react";
import { beforeEach, describe, expect, it, vi } from "vitest";

import { ACTION_ERROR_STATUS, USAGE_LIMIT_MESSAGE } from "@/lib/action-errors";

import { getCrossProviderComplianceOverview } from "../_actions/cross-provider";
import { CROSS_PROVIDER_FRAMEWORKS } from "../_lib/cross-provider-frameworks";
import type { CrossProviderOverviewResult } from "../_types";
import {
  CROSS_PROVIDER_OVERVIEW_LOAD_ERROR_MESSAGE,
  CROSS_PROVIDER_OVERVIEW_RESULT_STATUS,
  CROSS_PROVIDER_OVERVIEW_TYPE,
} from "../_types";
import { CrossProviderOverview } from "./cross-provider-overview";

vi.mock("../_actions/cross-provider", () => ({
  getCrossProviderComplianceOverview: vi.fn(),
}));

vi.mock("@/actions/providers", () => ({
  getAllProviders: vi.fn().mockResolvedValue({ data: [] }),
}));

vi.mock("@/actions/manage-groups/manage-groups", () => ({
  getAllProviderGroups: vi.fn().mockResolvedValue({ data: [] }),
}));

vi.mock("./cross-provider-filters", () => ({
  CrossProviderFilters: () => <div data-testid="cross-provider-filters" />,
}));

vi.mock("./cross-provider-framework-card", () => ({
  CrossProviderFrameworkCard: ({ title }: { title: string }) => (
    <div data-testid="framework-card">{title}</div>
  ),
}));

const successResult = (complianceId: string): CrossProviderOverviewResult => ({
  status: CROSS_PROVIDER_OVERVIEW_RESULT_STATUS.SUCCESS,
  response: {
    data: {
      type: CROSS_PROVIDER_OVERVIEW_TYPE,
      id: complianceId,
      attributes: {
        compliance_id: complianceId,
        framework: complianceId,
        name: complianceId,
        version: "1.0",
        description: "",
        compatible_providers: ["aws"],
        requested_providers: ["aws"],
        providers: ["aws"],
        scan_ids: [],
        scan_ids_by_provider: {},
        requirements_passed: 1,
        requirements_failed: 0,
        requirements_manual: 0,
        total_requirements: 1,
        requirements: [],
      },
    },
  },
});

const loadErrorResult: CrossProviderOverviewResult = {
  status: CROSS_PROVIDER_OVERVIEW_RESULT_STATUS.LOAD_ERROR,
  message: CROSS_PROVIDER_OVERVIEW_LOAD_ERROR_MESSAGE,
};

const renderOverview = async () =>
  render(await CrossProviderOverview({ searchParams: {} }));

describe("CrossProviderOverview", () => {
  beforeEach(() => {
    vi.mocked(getCrossProviderComplianceOverview).mockReset();
  });

  it("degrades to a partial view when a single framework fails to load", async () => {
    // Given: DORA fails, the other frameworks load
    vi.mocked(getCrossProviderComplianceOverview).mockImplementation(
      async ({ complianceId }) =>
        complianceId === "dora_2022_2554"
          ? loadErrorResult
          : successResult(complianceId),
    );

    // When
    await renderOverview();

    // Then: loaded cards render, the failed framework is called out by name
    expect(screen.getAllByTestId("framework-card")).toHaveLength(
      CROSS_PROVIDER_FRAMEWORKS.length - 1,
    );
    expect(screen.getByText(/Could not load DORA/)).toBeInTheDocument();
    expect(
      screen.queryByText(CROSS_PROVIDER_OVERVIEW_LOAD_ERROR_MESSAGE),
    ).not.toBeInTheDocument();
  });

  it("replaces the tab with the error alert when every framework fails to load", async () => {
    // Given
    vi.mocked(getCrossProviderComplianceOverview).mockResolvedValue(
      loadErrorResult,
    );

    // When
    await renderOverview();

    // Then
    expect(
      screen.getByText(CROSS_PROVIDER_OVERVIEW_LOAD_ERROR_MESSAGE),
    ).toBeInTheDocument();
    expect(screen.queryByTestId("framework-card")).not.toBeInTheDocument();
  });

  it("gates the whole tab on an action error even if other frameworks loaded", async () => {
    // Given: one framework hits the usage limit (402)
    vi.mocked(getCrossProviderComplianceOverview).mockImplementation(
      async ({ complianceId }) =>
        complianceId === "dora_2022_2554"
          ? {
              status: CROSS_PROVIDER_OVERVIEW_RESULT_STATUS.ACTION_ERROR,
              result: { status: ACTION_ERROR_STATUS.PAYMENT_REQUIRED },
            }
          : successResult(complianceId),
    );

    // When
    await renderOverview();

    // Then
    expect(
      screen.getByText(new RegExp(USAGE_LIMIT_MESSAGE)),
    ).toBeInTheDocument();
    expect(screen.queryByTestId("framework-card")).not.toBeInTheDocument();
  });
});
