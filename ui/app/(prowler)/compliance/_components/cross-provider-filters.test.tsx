import { render, screen } from "@testing-library/react";
import type { ReactNode } from "react";
import { describe, expect, it, vi } from "vitest";

import { CrossProviderFilters } from "./cross-provider-filters";

vi.mock("next/navigation", () => ({
  useSearchParams: () => new URLSearchParams(),
}));

vi.mock("@/hooks/use-url-filters", () => ({
  useUrlFilters: () => ({ updateFilter: vi.fn() }),
}));

vi.mock("@/components/filters/clear-filters-button", () => ({
  ClearFiltersButton: () => <button>Clear filters</button>,
}));

vi.mock("@/components/shadcn/select/multiselect", () => ({
  MultiSelect: ({ children }: { children: ReactNode }) => <div>{children}</div>,
  MultiSelectTrigger: ({
    children,
    ...props
  }: {
    children: ReactNode;
    "aria-label"?: string;
  }) => (
    <button role="combobox" {...props}>
      {children}
    </button>
  ),
  MultiSelectValue: ({ placeholder }: { placeholder: string }) => (
    <span>{placeholder}</span>
  ),
  MultiSelectContent: ({ children }: { children: ReactNode }) => (
    <div>{children}</div>
  ),
  MultiSelectItem: ({ children }: { children: ReactNode }) => (
    <div>{children}</div>
  ),
  MultiSelectSelectAll: ({ children }: { children: ReactNode }) => (
    <div>{children}</div>
  ),
  MultiSelectSeparator: () => <hr />,
}));

describe("CrossProviderFilters", () => {
  it("shows only the three cross-provider filters with product copy", () => {
    // Given / When
    render(
      <CrossProviderFilters
        providerTypes={["aws", "azure"]}
        providerAccounts={[
          { id: "provider-1", label: "Production", type: "aws" },
        ]}
        providerGroups={[{ id: "group-1", name: "Critical" }]}
      />,
    );

    // Then
    expect(
      screen.getByRole("combobox", { name: "Provider type" }),
    ).toBeInTheDocument();
    expect(
      screen.getByRole("combobox", { name: "Providers" }),
    ).toBeInTheDocument();
    expect(
      screen.getByRole("combobox", { name: "Provider group" }),
    ).toBeInTheDocument();
    expect(screen.getAllByRole("combobox")).toHaveLength(3);
  });
});
