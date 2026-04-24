import { render, screen, within } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";

import { DATA_TABLE_FILTER_MODE } from "@/types/filters";

const mockSetPending = vi.fn();
const mockApplyAll = vi.fn();
const mockDiscardAll = vi.fn();
const mockClearAndApply = vi.fn();
const mockGetFilterValue = vi.fn().mockReturnValue([]);

vi.mock("@/hooks/use-filter-batch", () => ({
  useFilterBatch: () => ({
    appliedFilters: {},
    pendingFilters: {
      "filter[severity__in]": ["critical"],
    },
    changedFilters: {
      "filter[severity__in]": ["critical"],
    },
    setPending: mockSetPending,
    applyAll: mockApplyAll,
    discardAll: mockDiscardAll,
    clearAndApply: mockClearAndApply,
    removeAppliedAndApply: vi.fn(),
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

vi.mock("@/components/filters/custom-checkbox-muted-findings", () => ({
  CustomCheckboxMutedFindings: () => <div>Muted selector</div>,
}));

vi.mock("@/components/filters/custom-date-picker", () => ({
  CustomDatePicker: () => <div>Date picker</div>,
}));

vi.mock("@/components/filters/data-filters", () => ({
  filterFindings: [],
}));

vi.mock("@/components/filters/filter-summary-strip", () => ({
  FilterSummaryStrip: ({
    chips,
    trailingContent,
  }: {
    chips: Array<{ displayValue?: string; value: string }>;
    trailingContent?: React.ReactNode;
  }) => (
    <div data-testid="filter-summary-strip">
      {chips.map((chip) => chip.displayValue ?? chip.value).join(",")}
      {trailingContent}
    </div>
  ),
}));

vi.mock("@/components/shadcn", () => ({
  Button: ({ children }: { children: React.ReactNode }) => (
    <button type="button">{children}</button>
  ),
}));

vi.mock("@/components/ui/expandable-section", () => ({
  ExpandableSection: ({
    children,
    contentClassName,
  }: {
    children: React.ReactNode;
    contentClassName?: string;
  }) => (
    <div data-testid="expandable-section" data-content-class={contentClassName}>
      {children}
    </div>
  ),
}));

vi.mock("@/components/ui/table", () => ({
  DataTableFilterCustom: ({
    mode,
    gridClassName,
  }: {
    mode?: string;
    gridClassName?: string;
  }) => (
    <div data-testid="data-table-filter-custom" data-grid-class={gridClassName}>
      {mode}
    </div>
  ),
}));

vi.mock("@/lib/categories", () => ({
  getCategoryLabel: (value: string) => value,
  getGroupLabel: (value: string) => value,
}));

import { FindingsFilters } from "./findings-filters";

describe("FindingsFilters", () => {
  it("uses batch mode controls and renders pending summary chips", () => {
    render(
      <FindingsFilters
        providers={[]}
        completedScanIds={["scan-1"]}
        scanDetails={[]}
        uniqueRegions={["eu-west-1"]}
        uniqueServices={["ec2"]}
        uniqueResourceTypes={["aws_instance"]}
        uniqueCategories={["security"]}
        uniqueGroups={["engineering_team"]}
      />,
    );

    expect(screen.getByTestId("data-table-filter-custom")).toHaveTextContent(
      DATA_TABLE_FILTER_MODE.BATCH,
    );
    expect(screen.getByTestId("data-table-filter-custom")).toHaveAttribute(
      "data-grid-class",
      "gap-3",
    );
    expect(screen.getByTestId("expandable-section")).toHaveAttribute(
      "data-content-class",
      "pt-0",
    );
    expect(screen.getByTestId("findings-expanded-filters")).toHaveClass(
      "hidden",
    );
    expect(screen.getByTestId("apply-filters-button")).toHaveTextContent(
      "true:1",
    );
    expect(
      screen.queryByTestId("clear-filters-button"),
    ).not.toBeInTheDocument();
    expect(screen.getByTestId("filter-summary-strip")).toHaveTextContent(
      "Critical",
    );
  });

  it("renders filter actions outside the selector controls row", () => {
    render(
      <FindingsFilters
        providers={[]}
        completedScanIds={["scan-1"]}
        scanDetails={[]}
        uniqueRegions={["eu-west-1"]}
        uniqueServices={["ec2"]}
        uniqueResourceTypes={["aws_instance"]}
        uniqueCategories={["security"]}
        uniqueGroups={["engineering_team"]}
      />,
    );

    const controls = screen.getByTestId("findings-filter-controls");
    const expandedFilters = screen.getByTestId("findings-expanded-filters");
    const pendingRow = screen.getByTestId("findings-pending-filter-row");

    expect(within(controls).getByText("Provider type selector")).toBeVisible();
    expect(within(controls).getByText("Accounts selector")).toBeVisible();
    expect(within(controls).getByText("Muted selector")).toBeVisible();
    expect(
      within(controls).queryByTestId("apply-filters-button"),
    ).not.toBeInTheDocument();
    expect(
      within(controls).queryByTestId("clear-filters-button"),
    ).not.toBeInTheDocument();
    expect(
      expandedFilters.compareDocumentPosition(pendingRow) &
        Node.DOCUMENT_POSITION_FOLLOWING,
    ).toBeTruthy();
    expect(
      within(pendingRow).getByTestId("apply-filters-button"),
    ).toBeVisible();
    expect(
      within(pendingRow).queryByTestId("clear-filters-button"),
    ).not.toBeInTheDocument();
  });
});
