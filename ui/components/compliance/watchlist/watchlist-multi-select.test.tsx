import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import type { ReactNode } from "react";
import { beforeEach, describe, expect, it, vi } from "vitest";

import { makeComplianceCatalogEntry } from "@/test-utils/compliance-watchlist";
import type { ComplianceCatalogEntry } from "@/types/compliance-watchlist";
import { UNIVERSAL_PROVIDER_TYPE } from "@/types/compliance-watchlist";

import { WatchlistMultiSelect } from "./watchlist-multi-select";

const { bulkUpdateComplianceWatchlistMock, toastMock } = vi.hoisted(() => ({
  bulkUpdateComplianceWatchlistMock: vi.fn(),
  toastMock: vi.fn(),
}));

vi.mock("@/actions/compliance-watchlist", () => ({
  bulkUpdateComplianceWatchlist: bulkUpdateComplianceWatchlistMock,
}));

vi.mock("@/components/shadcn/toast/use-toast", () => ({
  useToast: () => ({ toast: toastMock }),
}));

// Faithful-enough stand-in for the popover primitive: it keeps the controlled
// `values`/`open` contract (which is what this component actually drives) and
// drops cmdk's virtualised listbox, which does not render in jsdom.
vi.mock("@/components/shadcn/select/multiselect", async () => {
  const { createContext, useContext } = await import("react");

  const Ctx = createContext<{
    values: string[];
    onValuesChange: (values: string[]) => void;
  }>({ values: [], onValuesChange: () => {} });

  return {
    MultiSelect: ({
      children,
      values,
      onValuesChange,
      onOpenChange,
    }: {
      children: ReactNode;
      values: string[];
      onValuesChange: (values: string[]) => void;
      onOpenChange: (open: boolean) => void;
    }) => (
      <Ctx.Provider value={{ values, onValuesChange }}>
        <button type="button" onClick={() => onOpenChange(true)}>
          open-dropdown
        </button>
        <button type="button" onClick={() => onOpenChange(false)}>
          close-dropdown
        </button>
        {children}
      </Ctx.Provider>
    ),
    MultiSelectTrigger: ({ children, ...props }: { children: ReactNode }) => (
      <button role="combobox" {...props}>
        {children}
      </button>
    ),
    MultiSelectContent: ({ children }: { children: ReactNode }) => (
      <div>{children}</div>
    ),
    MultiSelectGroup: ({
      heading,
      children,
    }: {
      heading: string;
      children: ReactNode;
    }) => (
      <div role="group" aria-label={heading}>
        <span>{heading}</span>
        {children}
      </div>
    ),
    MultiSelectItem: ({
      value,
      children,
    }: {
      value: string;
      children: ReactNode;
    }) => {
      const { values, onValuesChange } = useContext(Ctx);
      const selected = values.includes(value);
      return (
        <button
          role="option"
          aria-selected={selected}
          onClick={() =>
            onValuesChange(
              selected
                ? values.filter((current) => current !== value)
                : [...values, value],
            )
          }
        >
          {children}
        </button>
      );
    },
  };
});

const ENTRIES: ComplianceCatalogEntry[] = [
  makeComplianceCatalogEntry({
    complianceId: "cis_controls_8.1",
    providerType: UNIVERSAL_PROVIDER_TYPE,
    framework: "CIS Controls",
  }),
  makeComplianceCatalogEntry({
    complianceId: "cis_1.4_aws",
    providerType: "aws",
    framework: "CIS",
    inWatchlist: true,
  }),
  makeComplianceCatalogEntry({
    complianceId: "cis_2.0_azure",
    providerType: "azure",
    framework: "CIS",
  }),
];

beforeEach(() => {
  bulkUpdateComplianceWatchlistMock.mockReset();
  bulkUpdateComplianceWatchlistMock.mockResolvedValue({ success: "ok" });
  toastMock.mockReset();
});

describe("WatchlistMultiSelect grouping", () => {
  it("labels the universal band separately from each provider type", () => {
    render(<WatchlistMultiSelect entries={ENTRIES} />);

    const universal = screen.getByRole("group", { name: "Universal" });
    expect(
      within(universal).getByText("CIS Controls - 1.0"),
    ).toBeInTheDocument();

    expect(
      within(screen.getByRole("group", { name: "AWS" })).getByText("CIS - 1.0"),
    ).toBeInTheDocument();
    expect(screen.getByRole("group", { name: "Azure" })).toBeInTheDocument();
  });
});

describe("WatchlistMultiSelect editing", () => {
  it("submits one diff for every change when the dropdown closes", async () => {
    const user = userEvent.setup();
    render(<WatchlistMultiSelect entries={ENTRIES} />);

    // When: pin Azure, unpin AWS, then close
    await user.click(screen.getByRole("button", { name: "open-dropdown" }));
    await user.click(
      within(screen.getByRole("group", { name: "Azure" })).getByRole("option"),
    );
    await user.click(
      within(screen.getByRole("group", { name: "AWS" })).getByRole("option"),
    );
    await user.click(screen.getByRole("button", { name: "close-dropdown" }));

    // Then
    await waitFor(() =>
      expect(bulkUpdateComplianceWatchlistMock).toHaveBeenCalledTimes(1),
    );
    expect(bulkUpdateComplianceWatchlistMock).toHaveBeenCalledWith({
      add: [{ complianceId: "cis_2.0_azure", providerType: "azure" }],
      remove: [{ complianceId: "cis_1.4_aws", providerType: "aws" }],
    });
  });

  it("does not call the API when the selection is unchanged", async () => {
    const user = userEvent.setup();
    render(<WatchlistMultiSelect entries={ENTRIES} />);

    // When
    await user.click(screen.getByRole("button", { name: "open-dropdown" }));
    await user.click(screen.getByRole("button", { name: "close-dropdown" }));

    // Then
    expect(bulkUpdateComplianceWatchlistMock).not.toHaveBeenCalled();
  });

  it("rolls the selection back when the write fails", async () => {
    bulkUpdateComplianceWatchlistMock.mockResolvedValue({ error: "403" });
    const user = userEvent.setup();
    render(<WatchlistMultiSelect entries={ENTRIES} />);

    // When
    await user.click(screen.getByRole("button", { name: "open-dropdown" }));
    await user.click(
      within(screen.getByRole("group", { name: "Azure" })).getByRole("option"),
    );
    await user.click(screen.getByRole("button", { name: "close-dropdown" }));

    // Then
    await waitFor(() =>
      expect(toastMock).toHaveBeenCalledWith(
        expect.objectContaining({ variant: "destructive" }),
      ),
    );
    expect(screen.getByRole("combobox")).toHaveTextContent(
      "Watchlist · 1 pinned",
    );
  });

  it("re-reads the server state when the dropdown is reopened", async () => {
    const user = userEvent.setup();
    const { rerender } = render(<WatchlistMultiSelect entries={ENTRIES} />);

    // When: a card pin lands from elsewhere while the dropdown is closed
    rerender(
      <WatchlistMultiSelect
        entries={ENTRIES.map((item) => ({ ...item, inWatchlist: true }))}
      />,
    );
    await user.click(screen.getByRole("button", { name: "open-dropdown" }));

    // Then
    expect(screen.getByRole("combobox")).toHaveTextContent(
      "Watchlist · 3 pinned",
    );
  });
});
