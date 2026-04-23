import { render, screen } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";

import { DATA_TABLE_FILTER_MODE } from "@/types/filters";

const mockSetPending = vi.fn();
const mockApplyAll = vi.fn();
const mockDiscardAll = vi.fn();
const mockClearAndApply = vi.fn();
const mockGetFilterValue = vi.fn().mockReturnValue([]);

vi.mock("@/hooks/use-filter-batch", () => ({
  useFilterBatch: () => ({
    pendingFilters: {
      "filter[region__in]": ["eu-west-1"],
    },
    setPending: mockSetPending,
    applyAll: mockApplyAll,
    discardAll: mockDiscardAll,
    clearAndApply: mockClearAndApply,
    hasChanges: true,
    changeCount: 1,
    getFilterValue: mockGetFilterValue,
  }),
}));

vi.mock("@/app/(prowler)/_overview/_components/provider-type-selector", () => ({
  ProviderTypeSelector: () => <div>Provider type selector</div>,
}));

vi.mock("@/app/(prowler)/_overview/_components/accounts-selector", () => ({
  AccountsSelector: () => <div>Accounts selector</div>,
}));

vi.mock("@/components/filters/apply-filters-button", () => ({
  ApplyFiltersButton: ({
    hasChanges,
    changeCount,
  }: {
    hasChanges: boolean;
    changeCount: number;
  }) => (
    <div data-testid="apply-filters-button">
      {String(hasChanges)}:{changeCount}
    </div>
  ),
}));

vi.mock("@/components/filters/clear-filters-button", () => ({
  ClearFiltersButton: ({ pendingCount }: { pendingCount?: number }) => (
    <div data-testid="clear-filters-button">{pendingCount ?? 0}</div>
  ),
}));

vi.mock("@/components/filters/filter-summary-strip", () => ({
  FilterSummaryStrip: ({
    chips,
  }: {
    chips: Array<{ displayValue?: string; value: string }>;
  }) => (
    <div data-testid="filter-summary-strip">
      {chips.map((chip) => chip.displayValue ?? chip.value).join(",")}
    </div>
  ),
}));

vi.mock("@/components/shadcn", () => ({
  Button: ({ children }: { children: React.ReactNode }) => (
    <button type="button">{children}</button>
  ),
}));

vi.mock("@/components/ui/expandable-section", () => ({
  ExpandableSection: ({ children }: { children: React.ReactNode }) => (
    <div>{children}</div>
  ),
}));

vi.mock("@/components/ui/table", () => ({
  DataTableFilterCustom: ({ mode }: { mode?: string }) => (
    <div data-testid="data-table-filter-custom">{mode}</div>
  ),
}));

import { ResourcesFilters } from "./resources-filters";

describe("ResourcesFilters", () => {
  it("uses batch mode controls and renders pending summary chips", () => {
    render(
      <ResourcesFilters
        providers={[]}
        uniqueRegions={["eu-west-1"]}
        uniqueServices={["ec2"]}
        uniqueResourceTypes={["aws_instance"]}
        uniqueGroups={["engineering_team"]}
      />,
    );

    expect(screen.getByTestId("data-table-filter-custom")).toHaveTextContent(
      DATA_TABLE_FILTER_MODE.BATCH,
    );
    expect(screen.getByTestId("apply-filters-button")).toHaveTextContent(
      "true:1",
    );
    expect(screen.getByTestId("clear-filters-button")).toHaveTextContent("1");
    expect(screen.getByTestId("filter-summary-strip")).toHaveTextContent(
      "eu-west-1",
    );
  });
});
