import { fireEvent, render, screen } from "@testing-library/react";
import { beforeEach, describe, expect, it, vi } from "vitest";

import { ComplianceFilters } from "./compliance-filters";

const { pushMock, updateFilterMock } = vi.hoisted(() => ({
  pushMock: vi.fn(),
  updateFilterMock: vi.fn(),
}));

let currentSearchParams = new URLSearchParams();

vi.mock("next/navigation", () => ({
  useRouter: () => ({ push: pushMock }),
  useSearchParams: () => currentSearchParams,
}));

vi.mock("@/hooks/use-url-filters", () => ({
  useUrlFilters: () => ({ updateFilter: updateFilterMock }),
}));

vi.mock("./scan-selector", () => ({
  ScanSelector: ({
    onSelectionChange,
  }: {
    onSelectionChange: (key: string) => void;
  }) => (
    <button
      data-testid="scan-selector"
      onClick={() => onSelectionChange("scan-2")}
    />
  ),
}));

vi.mock("@/components/filters/provider-account-selectors", () => ({
  ProviderAccountSelectors: ({
    paramsToDeleteOnChange,
  }: {
    paramsToDeleteOnChange?: string[];
  }) => (
    <div
      data-testid="provider-account-selectors"
      data-params={(paramsToDeleteOnChange ?? []).join(",")}
    />
  ),
}));

vi.mock("@/components/filters/provider-group-selector", () => ({
  ProviderGroupSelector: ({
    paramsToDeleteOnChange,
  }: {
    paramsToDeleteOnChange?: string[];
  }) => (
    <div
      data-testid="provider-group-selector"
      data-params={(paramsToDeleteOnChange ?? []).join(",")}
    />
  ),
}));

vi.mock("@/components/filters/clear-filters-button", () => ({
  ClearFiltersButton: () => <div data-testid="clear-filters" />,
}));

vi.mock("@/components/shadcn/select/multiselect", () => ({
  MultiSelect: ({ children }: { children: React.ReactNode }) => (
    <div data-testid="region-multiselect">{children}</div>
  ),
  MultiSelectTrigger: ({ children }: { children: React.ReactNode }) => (
    <div>{children}</div>
  ),
  MultiSelectValue: ({ placeholder }: { placeholder: string }) => (
    <span>{placeholder}</span>
  ),
  MultiSelectContent: ({ children }: { children: React.ReactNode }) => (
    <div>{children}</div>
  ),
  MultiSelectItem: ({ children }: { children: React.ReactNode }) => (
    <div>{children}</div>
  ),
  MultiSelectSelectAll: ({ children }: { children: React.ReactNode }) => (
    <div>{children}</div>
  ),
  MultiSelectSeparator: () => <hr />,
}));

const defaultProps = {
  scans: [],
  uniqueRegions: ["eu-west-1"],
  selectedScanId: "scan-1",
  providers: [],
  providerGroups: [],
};

beforeEach(() => {
  vi.clearAllMocks();
  currentSearchParams = new URLSearchParams();
});

describe("ComplianceFilters", () => {
  it("renders the scan, provider type/account, provider group and region selectors", () => {
    render(<ComplianceFilters {...defaultProps} />);

    expect(screen.getByTestId("scan-selector")).toBeInTheDocument();
    expect(
      screen.getByTestId("provider-account-selectors"),
    ).toBeInTheDocument();
    expect(screen.getByTestId("provider-group-selector")).toBeInTheDocument();
    expect(screen.getByTestId("region-multiselect")).toBeInTheDocument();
  });

  it("wires the provider selectors to clear scanId + page on change (reverse XOR)", () => {
    render(<ComplianceFilters {...defaultProps} />);

    for (const testId of [
      "provider-account-selectors",
      "provider-group-selector",
    ]) {
      const params = screen.getByTestId(testId).getAttribute("data-params");
      expect(params).toContain("scanId");
      expect(params).toContain("page");
    }
  });

  it("clears provider-scope filters and page when a scan is selected", () => {
    currentSearchParams = new URLSearchParams(
      "scanId=scan-1&filter[provider_type__in]=aws&filter[provider_id__in]=p1&filter[provider_groups__in]=g1&filter[region__in]=eu-west-1&page=2",
    );

    render(<ComplianceFilters {...defaultProps} />);
    fireEvent.click(screen.getByTestId("scan-selector"));

    expect(pushMock).toHaveBeenCalledTimes(1);
    const pushedUrl = new URL(
      pushMock.mock.calls[0][0] as string,
      "https://example.com",
    );
    const params = pushedUrl.searchParams;

    expect(params.get("scanId")).toBe("scan-2");
    expect(params.get("filter[provider_type__in]")).toBeNull();
    expect(params.get("filter[provider_id__in]")).toBeNull();
    expect(params.get("filter[provider_groups__in]")).toBeNull();
    expect(params.get("page")).toBeNull();
    // region is independent of the scan/provider XOR and must survive
    expect(params.get("filter[region__in]")).toBe("eu-west-1");
  });
});
