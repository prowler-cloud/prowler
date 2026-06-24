import { render, screen } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";

import type { FilterOption } from "@/types/filters";
import type { ProviderProps } from "@/types/providers";

vi.mock("next/navigation", () => ({
  useSearchParams: () => new URLSearchParams(),
}));

vi.mock("@/hooks/use-url-filters", () => ({
  useUrlFilters: () => ({ updateFilter: vi.fn() }),
}));

vi.mock("@/app/(prowler)/_overview/_components/provider-type-selector", () => ({
  ProviderTypeSelector: () => <div>Provider type selector</div>,
}));

vi.mock("@/components/filters/clear-filters-button", () => ({
  ClearFiltersButton: () => <button type="button">Clear</button>,
}));

vi.mock("@/components/ui/entities/entity-info", () => ({
  EntityInfo: () => null,
}));

vi.mock("@/lib/helper-filters", () => ({
  isConnectionStatus: () => false,
  isGroupFilterEntity: () => false,
}));

vi.mock("@/components/shadcn/select/multiselect", () => ({
  MultiSelect: ({ children }: { children: React.ReactNode }) => (
    <div>{children}</div>
  ),
  MultiSelectTrigger: ({ children }: { children: React.ReactNode }) => (
    <div>{children}</div>
  ),
  MultiSelectValue: ({ placeholder }: { placeholder: string }) => (
    <span>{placeholder}</span>
  ),
  MultiSelectContent: ({
    children,
    search,
  }: {
    children: React.ReactNode;
    search?: boolean | { placeholder?: string };
  }) => (
    <div
      data-testid="multiselect-content"
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

import { ProvidersFilters } from "./providers-filters";

const filters: FilterOption[] = [
  {
    key: "filter[group__in]",
    labelCheckboxGroup: "Groups",
    values: ["engineering"],
  },
];

const providers: ProviderProps[] = [];

describe("ProvidersFilters", () => {
  it("enables searchable provider filter dropdowns", () => {
    render(<ProvidersFilters filters={filters} providers={providers} />);

    expect(screen.getByTestId("multiselect-content")).toHaveAttribute(
      "data-search-placeholder",
      "Search groups...",
    );
  });
});
