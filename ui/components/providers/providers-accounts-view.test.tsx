import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import type { ReactNode } from "react";
import { afterEach, describe, expect, it, vi } from "vitest";

import type { FilterOption, MetaDataProps, ProviderProps } from "@/types";
import type { ProvidersTableRow } from "@/types/providers-table";

const { refreshMock, replaceMock, searchParamsValue } = vi.hoisted(() => ({
  refreshMock: vi.fn(),
  replaceMock: vi.fn(),
  searchParamsValue: { current: "" },
}));

vi.mock("next/navigation", () => ({
  usePathname: () => "/providers",
  useRouter: () => ({
    refresh: refreshMock,
    replace: replaceMock,
  }),
  useSearchParams: () => new URLSearchParams(searchParamsValue.current),
}));

vi.mock("@/components/providers/table", () => ({
  SkeletonTableProviders: () => <div data-testid="providers-skeleton" />,
}));

vi.mock("@/components/providers/add-provider-button", () => ({
  AddProviderButton: ({ onOpenWizard }: { onOpenWizard: () => void }) => (
    <button type="button" onClick={onOpenWizard}>
      Add Provider
    </button>
  ),
}));

vi.mock("@/components/providers/muted-findings-config-button", () => ({
  MutedFindingsConfigButton: () => (
    <button type="button">Muted findings config</button>
  ),
}));

vi.mock("@/components/providers/providers-filters", () => ({
  ProvidersFilters: ({ actions }: { actions: ReactNode }) => (
    <div data-testid="providers-filters">
      Filters
      {actions}
    </div>
  ),
}));

vi.mock("@/components/providers/providers-accounts-table", () => ({
  ProvidersAccountsTable: () => <div data-testid="providers-table">Table</div>,
}));

vi.mock("@/components/providers/wizard", () => ({
  ProviderWizardModal: ({
    open,
    onOpenChange,
  }: {
    open: boolean;
    onOpenChange: (open: boolean) => void;
  }) =>
    open ? (
      <div role="dialog">
        Provider wizard
        <button type="button" onClick={() => onOpenChange(false)}>
          Close
        </button>
      </div>
    ) : null,
}));

import { ProvidersAccountsView } from "./providers-accounts-view";

const filters: FilterOption[] = [];
const providers: ProviderProps[] = [];
const rows: ProvidersTableRow[] = [];
const metadata: MetaDataProps = {
  pagination: { page: 1, pages: 1, count: 0, itemsPerPage: [10] },
  version: "latest",
};

const disconnectedProviders: ProviderProps[] = [
  {
    id: "provider-1",
    type: "providers",
    attributes: {
      provider: "aws",
      uid: "123456789012",
      alias: "Production",
      status: "completed",
      resources: 0,
      connection: {
        connected: false,
        last_checked_at: "2026-04-13T00:00:00Z",
      },
      scanner_args: {
        only_logs: false,
        excluded_checks: [],
        aws_retries_max_attempts: 3,
      },
      inserted_at: "2026-04-13T00:00:00Z",
      updated_at: "2026-04-13T00:00:00Z",
      created_by: {
        object: "user",
        id: "user-1",
      },
    },
    relationships: {
      secret: {
        data: null,
      },
      provider_groups: {
        meta: {
          count: 0,
        },
        data: [],
      },
    },
  },
];

describe("ProvidersAccountsView", () => {
  afterEach(() => {
    vi.restoreAllMocks();
    searchParamsValue.current = "";
    window.history.replaceState({}, "", "/");
  });

  it("shows a full page empty state without filters or table when there are no providers", () => {
    // Given/When
    render(
      <ProvidersAccountsView
        isCloud={false}
        filters={filters}
        metadata={metadata}
        providers={providers}
        rows={rows}
      />,
    );

    // Then
    expect(screen.getByText("No Providers Configured")).toBeInTheDocument();
    expect(
      screen.getByRole("region", { name: /no providers configured/i }),
    ).toHaveClass("min-h-[calc(100dvh-28rem)]");
    expect(screen.queryByTestId("providers-filters")).not.toBeInTheDocument();
    expect(screen.queryByTestId("providers-table")).not.toBeInTheDocument();
  });

  it("opens the provider wizard from the no providers CTA", async () => {
    // Given
    const user = userEvent.setup();

    render(
      <ProvidersAccountsView
        isCloud={false}
        filters={filters}
        metadata={metadata}
        providers={providers}
        rows={rows}
      />,
    );

    // When
    await user.click(
      screen.getByRole("button", { name: /open add provider modal/i }),
    );

    // Then
    expect(screen.getByRole("dialog")).toHaveTextContent("Provider wizard");
  });

  it("opens the provider wizard from the URL without immediately clearing the one-shot intent", () => {
    // Given
    searchParamsValue.current = "tab=connected&addProvider=true";
    window.history.replaceState(
      {},
      "",
      "/providers?tab=connected&addProvider=true",
    );
    // Spy only after the URL setup so we measure what the component does on mount.
    const replaceStateSpy = vi.spyOn(window.history, "replaceState");

    render(
      <ProvidersAccountsView
        isCloud={false}
        filters={filters}
        metadata={metadata}
        providers={providers}
        rows={rows}
      />,
    );

    // Then
    expect(screen.getByRole("dialog")).toHaveTextContent("Provider wizard");
    expect(replaceStateSpy).not.toHaveBeenCalled();
  });

  it("cleans the one-shot intent from the URL without refetching when the URL-opened wizard closes", async () => {
    // Given
    searchParamsValue.current = "tab=connected&addProvider=true";
    const replaceStateSpy = vi.spyOn(window.history, "replaceState");
    const user = userEvent.setup();

    render(
      <ProvidersAccountsView
        isCloud={false}
        filters={filters}
        metadata={metadata}
        providers={providers}
        rows={rows}
      />,
    );

    // When
    await user.click(screen.getByRole("button", { name: /close/i }));

    // Then
    expect(screen.queryByRole("dialog")).not.toBeInTheDocument();
    // The URL is cleaned via the History API (no RSC refetch). We must NOT
    // refresh/replace here: re-running the /providers Server Component on close
    // read as a full page reload. The provider-creation actions already
    // revalidatePath("/providers"), so the table is fresh behind the modal.
    expect(replaceStateSpy).toHaveBeenCalledWith(
      null,
      "",
      "/providers?tab=connected",
    );
    expect(refreshMock).not.toHaveBeenCalled();
    expect(replaceMock).not.toHaveBeenCalled();
  });

  it("does not touch the URL or refetch when a manually opened wizard closes", async () => {
    // Given: no addProvider param in the URL, wizard opened via the CTA.
    searchParamsValue.current = "";
    const replaceStateSpy = vi.spyOn(window.history, "replaceState");
    const user = userEvent.setup();

    render(
      <ProvidersAccountsView
        isCloud={false}
        filters={filters}
        metadata={metadata}
        providers={providers}
        rows={rows}
      />,
    );

    // When: open the wizard from the empty-state CTA, then close it.
    await user.click(
      screen.getByRole("button", { name: /open add provider modal/i }),
    );
    await user.click(screen.getByRole("button", { name: /close/i }));

    // Then: nothing to clean and no refresh — the creation actions own the
    // data refresh via revalidatePath.
    expect(screen.queryByRole("dialog")).not.toBeInTheDocument();
    expect(replaceStateSpy).not.toHaveBeenCalled();
    expect(refreshMock).not.toHaveBeenCalled();
    expect(replaceMock).not.toHaveBeenCalled();
  });

  it("keeps filters and table visible when providers are disconnected", () => {
    // Given/When
    render(
      <ProvidersAccountsView
        isCloud={false}
        filters={filters}
        metadata={metadata}
        providers={disconnectedProviders}
        rows={rows}
      />,
    );

    // Then
    expect(screen.getByTestId("providers-filters").parentElement).toHaveClass(
      "flex",
      "flex-col",
      "gap-6",
    );
    expect(screen.getByTestId("providers-table")).toBeInTheDocument();
    expect(
      screen.queryByText("No Providers Configured"),
    ).not.toBeInTheDocument();
  });

  it("opens the provider wizard from the normal Add Provider button", async () => {
    // Given
    const user = userEvent.setup();

    render(
      <ProvidersAccountsView
        isCloud={false}
        filters={filters}
        metadata={metadata}
        providers={disconnectedProviders}
        rows={rows}
      />,
    );

    // When
    await user.click(screen.getByRole("button", { name: /add provider/i }));

    // Then
    expect(screen.getByRole("dialog")).toHaveTextContent("Provider wizard");
  });
});
