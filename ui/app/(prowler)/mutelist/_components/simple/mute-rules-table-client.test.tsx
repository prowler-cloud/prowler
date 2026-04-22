import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import type { ReactNode } from "react";
import { describe, expect, it, vi } from "vitest";

const { deleteMuteRuleMock, toastMock, routerRefreshMock } = vi.hoisted(() => ({
  deleteMuteRuleMock: vi.fn(),
  toastMock: vi.fn(),
  routerRefreshMock: vi.fn(),
}));

vi.mock("next/navigation", () => ({
  useRouter: () => ({
    refresh: routerRefreshMock,
  }),
}));

vi.mock("@/actions/mute-rules", () => ({
  deleteMuteRule: deleteMuteRuleMock,
}));

vi.mock("@/components/ui", () => ({
  useToast: () => ({
    toast: toastMock,
  }),
}));

vi.mock("@/components/shadcn", () => ({
  Button: ({
    children,
    ...props
  }: React.ButtonHTMLAttributes<HTMLButtonElement>) => (
    <button {...props}>{children}</button>
  ),
  CardTitle: ({ children }: { children: ReactNode }) => <h3>{children}</h3>,
}));

vi.mock("@/components/shadcn/modal", () => ({
  Modal: ({
    children,
    open,
    title,
  }: {
    children: ReactNode;
    open: boolean;
    title?: string;
  }) =>
    open ? (
      <div role="dialog" aria-label={title}>
        {children}
      </div>
    ) : null,
}));

const dataTableMock = vi.fn();

vi.mock("@/components/ui/table", () => ({
  DataTable: (props: {
    columns: Array<{
      id?: string;
      cell?: (args: { row: { original: unknown } }) => ReactNode;
    }>;
    data: unknown[];
    enableRowSelection?: boolean;
    showSearch?: boolean;
    getRowId?: (row: unknown) => string;
  }) => {
    dataTableMock(props);
    const actionsColumn = props.columns.find(
      (column) => column.id === "actions",
    );
    const findingsColumn = props.columns[3];

    return (
      <div>
        {props.data.map((row, index) => (
          <div key={index}>
            {findingsColumn?.cell?.({ row: { original: row } })}
            {actionsColumn?.cell?.({ row: { original: row } })}
          </div>
        ))}
      </div>
    );
  },
}));

vi.mock("./floating-bulk-delete-button", () => ({
  FloatingBulkDeleteButton: () => (
    <div data-testid="floating-bulk-delete-button" />
  ),
}));

vi.mock("@/components/shadcn/dropdown", () => ({
  ActionDropdown: ({ children }: { children: ReactNode }) => (
    <div>{children}</div>
  ),
  ActionDropdownDangerZone: ({ children }: { children: ReactNode }) => (
    <div>{children}</div>
  ),
  ActionDropdownItem: ({
    label,
    onSelect,
  }: {
    label: string;
    onSelect?: () => void;
  }) => (
    <button type="button" onClick={onSelect}>
      {label}
    </button>
  ),
}));

vi.mock("./mute-rule-edit-form", () => ({
  MuteRuleEditForm: () => null,
}));

vi.mock("./mute-rule-targets-modal", () => ({
  MuteRuleTargetsModal: ({
    muteRule,
    open,
  }: {
    muteRule: { targetLabels?: string[] } | null;
    open: boolean;
  }) =>
    open ? (
      <div role="dialog" aria-label="Muted Findings">
        {muteRule?.targetLabels?.map((label) => (
          <span key={label}>{label}</span>
        ))}
      </div>
    ) : null,
}));

import { MuteRulesTableClient } from "./mute-rules-table-client";

const muteRule = {
  type: "mute-rules" as const,
  id: "mute-rule-1",
  attributes: {
    inserted_at: "2026-04-22T09:00:00Z",
    updated_at: "2026-04-22T09:05:00Z",
    name: "Ignore dev bucket",
    reason: "Existing reason",
    enabled: true,
    finding_uids: ["uid-1", "uid-2", "uid-3"],
  },
  targetLabels: ["Check title • bucket-a", "Other check • bucket-b", "uid-3"],
  targetSummaryLabel: "Check title • bucket-a",
  hiddenTargetCount: 2,
};

describe("MuteRulesTableClient", () => {
  it("deletes a mute rule with a single toast", async () => {
    deleteMuteRuleMock.mockResolvedValue({
      success: "Mute rule deleted successfully!",
    });

    const user = userEvent.setup();

    render(<MuteRulesTableClient muteRules={[muteRule]} />);

    await user.click(screen.getByRole("button", { name: "Delete Mute Rule" }));
    await user.click(screen.getByRole("button", { name: "Delete" }));

    await waitFor(() => {
      expect(deleteMuteRuleMock).toHaveBeenCalledTimes(1);
      expect(toastMock).toHaveBeenCalledTimes(1);
      expect(toastMock).toHaveBeenCalledWith({
        title: "Success",
        description: "Mute rule deleted successfully!",
      });
      expect(routerRefreshMock).toHaveBeenCalledTimes(1);
    });
  });

  it("opens the muted findings modal from the actionable findings cell", async () => {
    const user = userEvent.setup();

    render(<MuteRulesTableClient muteRules={[muteRule]} />);

    await user.click(
      screen.getByRole("button", {
        name: "View muted findings for Ignore dev bucket",
      }),
    );

    expect(
      screen.getByRole("dialog", { name: "Muted Findings" }),
    ).toBeInTheDocument();
    expect(screen.getByText("Check title • bucket-a")).toBeInTheDocument();
    expect(screen.getByText("Other check • bucket-b")).toBeInTheDocument();
    expect(screen.getByText("uid-3")).toBeInTheDocument();
  });

  it("wires the DataTable for selection and search, and hides the floating button with no selection", () => {
    dataTableMock.mockClear();

    render(<MuteRulesTableClient muteRules={[muteRule]} />);

    expect(dataTableMock).toHaveBeenCalled();
    const props = dataTableMock.mock.calls[0][0];
    expect(props.enableRowSelection).toBe(true);
    expect(props.showSearch).toBe(true);
    expect(props.getRowId?.(muteRule)).toBe("mute-rule-1");

    expect(
      screen.queryByTestId("floating-bulk-delete-button"),
    ).not.toBeInTheDocument();
  });
});
