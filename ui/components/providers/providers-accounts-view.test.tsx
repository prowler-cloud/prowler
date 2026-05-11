import { render, screen } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";

import type { FilterOption, MetaDataProps, ProviderProps } from "@/types";
import type { ProvidersTableRow } from "@/types/providers-table";

vi.mock("@/components/providers/add-provider-button", () => ({
  AddProviderButton: () => <button type="button">Add provider</button>,
}));

vi.mock("@/components/providers/muted-findings-config-button", () => ({
  MutedFindingsConfigButton: () => (
    <button type="button">Muted findings config</button>
  ),
}));

vi.mock("@/components/providers/providers-filters", () => ({
  ProvidersFilters: () => <div data-testid="providers-filters">Filters</div>,
}));

vi.mock("@/components/providers/providers-accounts-table", () => ({
  ProvidersAccountsTable: () => <div data-testid="providers-table">Table</div>,
}));

vi.mock("@/components/providers/wizard", () => ({
  ProviderWizardModal: () => <div data-testid="provider-wizard-modal" />,
}));

import { ProvidersAccountsView } from "./providers-accounts-view";

const filters: FilterOption[] = [];
const providers: ProviderProps[] = [];
const rows: ProvidersTableRow[] = [];
const metadata: MetaDataProps = {
  pagination: { page: 1, pages: 1, count: 0, itemsPerPage: [10] },
  version: "latest",
};

describe("ProvidersAccountsView", () => {
  it("keeps the same vertical spacing between filters and table as other views", () => {
    render(
      <ProvidersAccountsView
        isCloud={false}
        filters={filters}
        metadata={metadata}
        providers={providers}
        rows={rows}
      />,
    );

    expect(screen.getByTestId("providers-filters").parentElement).toHaveClass(
      "flex",
      "flex-col",
      "gap-6",
    );
    expect(screen.getByTestId("providers-table")).toBeInTheDocument();
  });
});
