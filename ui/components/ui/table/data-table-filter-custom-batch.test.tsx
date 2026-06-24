import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeEach, describe, expect, it, vi } from "vitest";

import { FilterOption } from "@/types/filters";

// ── next/navigation mock ────────────────────────────────────────────────────
const mockPush = vi.fn();
const mockUpdateFilter = vi.fn();

vi.mock("next/navigation", () => ({
  useRouter: () => ({ push: mockPush }),
  usePathname: () => "/findings",
  useSearchParams: () => new URLSearchParams(),
}));

// ── useUrlFilters mock — tracks whether updateFilter is called ───────────────
vi.mock("@/hooks/use-url-filters", () => ({
  useUrlFilters: () => ({ updateFilter: mockUpdateFilter }),
}));

// ── context (optional dependency used by useUrlFilters) ────────────────────
vi.mock("@/contexts", () => ({
  useFilterTransitionOptional: () => null,
}));

// ── MultiSelect mock — renders a simple <select> backed by onValuesChange ──
//    This lets us trigger filter changes without needing the full Popover UI.
vi.mock("@/components/shadcn/select/multiselect", () => ({
  MultiSelect: ({
    children,
    values,
    onValuesChange,
  }: {
    children: React.ReactNode;
    values?: string[];
    onValuesChange?: (values: string[]) => void;
  }) => (
    <div data-testid="multiselect" data-values={JSON.stringify(values ?? [])}>
      {children}
      {/* expose a select to drive value changes in tests */}
      <select
        data-testid="multiselect-trigger"
        multiple
        defaultValue={values ?? []}
        onChange={(e) => {
          const selected = Array.from(e.target.selectedOptions).map(
            (o) => o.value,
          );
          onValuesChange?.(selected);
        }}
      >
        <option value="critical">critical</option>
        <option value="high">high</option>
        <option value="FAIL">FAIL</option>
      </select>
    </div>
  ),
  MultiSelectTrigger: ({ children }: { children: React.ReactNode }) => (
    <div>{children}</div>
  ),
  MultiSelectValue: ({ placeholder }: { placeholder: string }) => (
    <span>{placeholder}</span>
  ),
  MultiSelectContent: ({
    children,
    width,
    search,
  }: {
    children: React.ReactNode;
    width?: string;
    search?: boolean | { placeholder?: string; emptyMessage?: string };
  }) => (
    <div
      data-testid="multiselect-content"
      data-width={width ?? "default"}
      data-search-placeholder={
        typeof search === "object" ? search.placeholder : String(search)
      }
    >
      {children}
    </div>
  ),
  MultiSelectSelectAll: ({ children }: { children: React.ReactNode }) => (
    <button type="button">{children}</button>
  ),
  MultiSelectSeparator: () => <hr />,
  MultiSelectItem: ({
    children,
    value,
  }: {
    children: React.ReactNode;
    value: string;
  }) => <option value={value}>{children}</option>,
}));

// ── ClearFiltersButton stub ─────────────────────────────────────────────────
vi.mock("@/components/filters/clear-filters-button", () => ({
  ClearFiltersButton: () => <button type="button">Clear</button>,
}));

// ── Other component stubs ───────────────────────────────────────────────────
vi.mock(
  "@/components/compliance/compliance-header/compliance-scan-info",
  () => ({
    ComplianceScanInfo: () => null,
  }),
);
vi.mock("@/components/ui/entities/entity-info", () => ({
  EntityInfo: () => null,
}));
vi.mock("@/lib/helper-filters", () => ({
  isScanEntity: () => false,
  isConnectionStatus: () => false,
}));

import { DataTableFilterCustom } from "./data-table-filter-custom";

// ── Future E2E coverage ────────────────────────────────────────────────────
// TODO (E2E): Integration tests for DataTableFilterCustom in batch mode:
// - In batch mode, selecting filters does NOT navigate the browser immediately
// - Multiple filter selections accumulate in pending state
// - Pressing Apply sends a single router.push with all staged filters
// - Pressing Discard reverts staged selections to match the current URL
// ──────────────────────────────────────────────────────────────────────────

const severityFilter: FilterOption = {
  key: "filter[severity__in]",
  labelCheckboxGroup: "Severity",
  values: ["critical", "high"],
};

const scanFilter: FilterOption = {
  key: "filter[scan__in]",
  labelCheckboxGroup: "Scan ID",
  values: ["scan-1"],
  width: "wide",
};

describe("DataTableFilterCustom — batch vs instant mode", () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  // ── Default / instant mode ───────────────────────────────────────────────

  describe("instant mode (default)", () => {
    it("should call updateFilter (URL update) when a selection changes", async () => {
      // Given
      const user = userEvent.setup();

      render(<DataTableFilterCustom filters={[severityFilter]} />);

      // When — simulate a value change on the mock select
      const select = screen.getByTestId("multiselect-trigger");
      await user.selectOptions(select, ["critical"]);

      // Then — instant mode pushes to URL via updateFilter
      expect(mockUpdateFilter).toHaveBeenCalledTimes(1);
      expect(mockUpdateFilter).toHaveBeenCalledWith(
        "filter[severity__in]",
        expect.any(Array),
      );
    });

    it("should NOT call onBatchChange in instant mode", async () => {
      // Given
      const user = userEvent.setup();
      const onBatchChange = vi.fn();

      render(
        <DataTableFilterCustom
          filters={[severityFilter]}
          onBatchChange={onBatchChange}
          // no mode prop → defaults to "instant"
        />,
      );

      // When
      const select = screen.getByTestId("multiselect-trigger");
      await user.selectOptions(select, ["critical"]);

      // Then
      expect(onBatchChange).not.toHaveBeenCalled();
    });

    it("should render without mode prop (backward compatibility)", () => {
      // Given / When
      render(<DataTableFilterCustom filters={[severityFilter]} />);

      // Then — renders without crashing
      expect(screen.getByText("All Severity")).toBeInTheDocument();
    });
  });

  // ── Batch mode ───────────────────────────────────────────────────────────

  describe("batch mode", () => {
    it("should call onBatchChange instead of updateFilter when selection changes", async () => {
      // Given
      const user = userEvent.setup();
      const onBatchChange = vi.fn();
      const getFilterValue = vi.fn().mockReturnValue([]);

      render(
        <DataTableFilterCustom
          filters={[severityFilter]}
          mode="batch"
          onBatchChange={onBatchChange}
          getFilterValue={getFilterValue}
        />,
      );

      // When
      const select = screen.getByTestId("multiselect-trigger");
      await user.selectOptions(select, ["critical"]);

      // Then — batch mode notifies caller instead of URL
      expect(onBatchChange).toHaveBeenCalledTimes(1);
      expect(onBatchChange).toHaveBeenCalledWith(
        "filter[severity__in]",
        expect.any(Array),
      );
      expect(mockUpdateFilter).not.toHaveBeenCalled();
    });

    it("should read selected values from getFilterValue in batch mode", () => {
      // Given — batch mode with pre-seeded pending state
      const onBatchChange = vi.fn();
      const getFilterValue = vi
        .fn()
        .mockImplementation((key: string) =>
          key === "filter[severity__in]" ? ["critical"] : [],
        );

      render(
        <DataTableFilterCustom
          filters={[severityFilter]}
          mode="batch"
          onBatchChange={onBatchChange}
          getFilterValue={getFilterValue}
        />,
      );

      // Then — the mock multiselect receives the pending values
      const multiselect = screen.getByTestId("multiselect");
      expect(multiselect).toHaveAttribute(
        "data-values",
        JSON.stringify(["critical"]),
      );

      // getFilterValue must have been called for the filter key
      expect(getFilterValue).toHaveBeenCalledWith("filter[severity__in]");
    });

    it("should pass empty array to MultiSelect when getFilterValue returns empty", () => {
      // Given
      const getFilterValue = vi.fn().mockReturnValue([]);

      render(
        <DataTableFilterCustom
          filters={[severityFilter]}
          mode="batch"
          onBatchChange={vi.fn()}
          getFilterValue={getFilterValue}
        />,
      );

      // Then — multiselect gets empty values
      const multiselect = screen.getByTestId("multiselect");
      expect(multiselect).toHaveAttribute("data-values", JSON.stringify([]));
    });
  });

  // ── hideClearButton ──────────────────────────────────────────────────────

  describe("hideClearButton prop", () => {
    it("should hide the ClearFiltersButton when hideClearButton is true", () => {
      // Given / When
      render(
        <DataTableFilterCustom
          filters={[severityFilter]}
          hideClearButton={true}
        />,
      );

      // Then
      expect(
        screen.queryByRole("button", { name: "Clear" }),
      ).not.toBeInTheDocument();
    });

    it("should show the ClearFiltersButton by default", () => {
      // Given / When
      render(<DataTableFilterCustom filters={[severityFilter]} />);

      // Then
      expect(screen.getByRole("button", { name: "Clear" })).toBeInTheDocument();
    });
  });

  describe("dropdown width", () => {
    it("should propagate the filter width to the dropdown content", () => {
      render(<DataTableFilterCustom filters={[scanFilter]} />);

      expect(screen.getByTestId("multiselect-content")).toHaveAttribute(
        "data-width",
        "wide",
      );
    });

    it("should enable searchable filter dropdowns by default", () => {
      render(<DataTableFilterCustom filters={[severityFilter]} />);

      expect(screen.getByTestId("multiselect-content")).toHaveAttribute(
        "data-search-placeholder",
        "Search severity...",
      );
    });
  });
});
