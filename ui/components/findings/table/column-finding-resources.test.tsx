import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import type {
  ButtonHTMLAttributes,
  InputHTMLAttributes,
  ReactNode,
} from "react";
import { describe, expect, it, vi } from "vitest";

// CustomLink pulls the "@/lib" barrel (and next-auth with it) into the unit env.
vi.mock("@/components/shadcn/custom/custom-link", () => ({
  CustomLink: ({ href, children }: { href: string; children: ReactNode }) => (
    <a href={href}>{children}</a>
  ),
}));

vi.mock("@/components/shadcn", async (importOriginal) => ({
  ...(await importOriginal<Record<string, unknown>>()),
  Button: ({ children, ...props }: ButtonHTMLAttributes<HTMLButtonElement>) => (
    <button {...props}>{children}</button>
  ),
  Checkbox: ({
    "aria-label": ariaLabel,
    onCheckedChange,
    ...props
  }: InputHTMLAttributes<HTMLInputElement> & {
    "aria-label"?: string;
    size?: string;
    onCheckedChange?: (checked: boolean) => void;
  }) => (
    <input
      type="checkbox"
      aria-label={ariaLabel}
      onChange={(event) => onCheckedChange?.(event.target.checked)}
      {...props}
    />
  ),
}));

vi.mock("@/components/findings/mute-findings-modal", () => ({
  MuteFindingsModal: () => null,
}));

vi.mock("@/components/findings/send-to-jira-modal", () => ({
  SendToJiraModal: ({
    findingId,
    isOpen,
  }: {
    findingId: string;
    isOpen: boolean;
  }) => (
    <div
      data-testid="jira-modal"
      data-finding-id={findingId}
      data-open={isOpen ? "true" : "false"}
    />
  ),
}));

vi.mock("@/components/icons/services/IconServices", () => ({
  JiraIcon: () => null,
}));

vi.mock("@/components/shadcn/dropdown", () => ({
  ActionDropdown: ({ children }: { children: ReactNode }) => (
    <div>{children}</div>
  ),
  ActionDropdownItem: ({
    label,
    onSelect,
    disabled,
  }: {
    label: string;
    onSelect?: () => void;
    disabled?: boolean;
  }) => (
    <button disabled={disabled} onClick={onSelect}>
      {label}
    </button>
  ),
}));

vi.mock("@/components/shadcn/info-field/info-field", () => ({
  InfoField: ({
    children,
    label,
  }: {
    children: ReactNode;
    label: string;
    variant?: string;
  }) => (
    <div>
      <span>{label}</span>
      <div>{children}</div>
    </div>
  ),
}));

vi.mock("@/components/shadcn/spinner/spinner", () => ({
  Spinner: () => null,
}));

vi.mock("@/components/shadcn/select/select", () => ({
  Select: ({ children }: { children: ReactNode }) => <div>{children}</div>,
  SelectContent: ({ children }: { children: ReactNode }) => (
    <div>{children}</div>
  ),
  SelectItem: ({ children }: { children: ReactNode }) => <div>{children}</div>,
  SelectTrigger: ({
    children,
    disabled,
    "aria-label": ariaLabel,
  }: {
    children: ReactNode;
    disabled?: boolean;
    "aria-label"?: string;
  }) => (
    <button aria-label={ariaLabel} disabled={disabled}>
      {children}
    </button>
  ),
  SelectValue: ({ children }: { children?: ReactNode }) => (
    <span>{children}</span>
  ),
}));

vi.mock("@/components/shadcn/tooltip", () => ({
  Tooltip: ({ children }: { children: ReactNode }) => <>{children}</>,
  TooltipContent: ({ children }: { children: ReactNode }) => (
    <span>{children}</span>
  ),
  TooltipTrigger: ({ children }: { children: ReactNode }) => <>{children}</>,
}));

vi.mock("@/components/shadcn/entities", () => ({
  DateWithTime: ({
    dateTime,
    inline,
  }: {
    dateTime: string | null;
    inline?: boolean;
  }) => <time data-inline={inline ? "true" : "false"}>{dateTime ?? "-"}</time>,
}));

vi.mock("@/components/shadcn/entities/entity-info", () => ({
  EntityInfo: ({
    entityAlias,
    entityId,
  }: {
    entityAlias?: string;
    entityId?: string;
  }) => (
    <div>
      <span>{entityAlias}</span>
      <span>{entityId}</span>
    </div>
  ),
}));

vi.mock("@/components/shadcn/table", () => ({
  SeverityBadge: ({ severity }: { severity: string }) => (
    <span>{severity}</span>
  ),
}));

vi.mock("@/components/shadcn/table/data-table-column-header", () => ({
  DataTableColumnHeader: ({ title }: { title: string }) => <span>{title}</span>,
}));

vi.mock("@/components/shadcn/table/status-finding-badge", () => ({
  StatusFindingBadge: ({ status }: { status: string }) => <span>{status}</span>,
}));

vi.mock("@/lib/date-utils", () => ({
  getFailingForLabel: () => "2d",
}));

const notificationIndicatorMock = vi.fn((_props: unknown) => null);

vi.mock("./notification-indicator", () => ({
  NotificationIndicator: (props: unknown) => {
    notificationIndicatorMock(props);
    return null;
  },
}));

import type { FindingResourceRow } from "@/types";
import {
  FINDING_TRIAGE_DISABLED_REASON,
  FINDING_TRIAGE_STATUS,
  type FindingTriageSummary,
} from "@/types/findings-triage";

import { getColumnFindingResources } from "./column-finding-resources";
import {
  CLOUD_ONLY_TOOLTIP_COPY,
  EDITING_UNAVAILABLE_COPY,
} from "./finding-triage-cells";

function makeTriageSummary(
  overrides?: Partial<FindingTriageSummary>,
): FindingTriageSummary {
  return {
    findingId: "finding-1",
    findingUid: "prowler-finding-uid-1",
    triageId: "triage-1",
    notesCount: 0,
    status: FINDING_TRIAGE_STATUS.UNDER_REVIEW,
    label: "Under Review",
    hasVisibleNote: false,
    isMuted: false,
    canEdit: true,
    billingHref: "https://prowler.com/pricing",
    ...overrides,
  };
}

function makeResource(
  overrides?: Partial<FindingResourceRow>,
): FindingResourceRow {
  return {
    id: "resource-row-1",
    rowType: "resource",
    findingId: "finding-1",
    checkId: "s3_check",
    providerType: "aws",
    providerAlias: "production",
    providerUid: "123456789",
    resourceName: "my-bucket",
    resourceType: "bucket",
    resourceGroup: "default",
    resourceUid: "arn:aws:s3:::my-bucket",
    service: "s3",
    region: "us-east-1",
    severity: "critical",
    status: "FAIL",
    delta: "new",
    isMuted: false,
    firstSeenAt: null,
    lastSeenAt: "2024-01-01T00:00:00Z",
    ...overrides,
  };
}

function getColumnIds(columns: ReturnType<typeof getColumnFindingResources>) {
  return columns.map(
    (column) =>
      (column as { id?: string; accessorKey?: string }).id ??
      (column as { id?: string; accessorKey?: string }).accessorKey,
  );
}

function renderResourceActionsCell({
  resource = makeResource(),
  onTriageUpdateAction,
  onTriageNoteLoadAction,
}: {
  resource?: FindingResourceRow;
  onTriageUpdateAction?: Parameters<
    typeof getColumnFindingResources
  >[0]["onTriageUpdateAction"];
  onTriageNoteLoadAction?: Parameters<
    typeof getColumnFindingResources
  >[0]["onTriageNoteLoadAction"];
} = {}) {
  const columns = getColumnFindingResources({
    rowSelection: {},
    selectableRowCount: 1,
    onTriageUpdateAction,
    onTriageNoteLoadAction,
  });

  const actionsColumn = columns.find(
    (col) => (col as { id?: string }).id === "actions",
  );
  if (!actionsColumn?.cell) {
    throw new Error("actions column not found");
  }
  const CellComponent = actionsColumn.cell as (props: {
    row: { original: FindingResourceRow };
  }) => ReactNode;

  render(<div>{CellComponent({ row: { original: resource } })}</div>);
}

describe("column-finding-resources", () => {
  it("should render actions as the last visible column after Triage without Notes", () => {
    // Given
    const columns = getColumnFindingResources({
      rowSelection: {},
      selectableRowCount: 1,
    });

    // When
    const columnIds = getColumnIds(columns);

    // Then
    expect(columnIds.slice(-2)).toEqual(["triage", "actions"]);
    expect(columnIds).not.toContain("notes");
    expect(
      (columns.at(-1) as { id?: string; size?: number } | undefined)?.size,
    ).toBe(56);
  });

  it("should render Open note in resource actions without exposing note preview metadata", () => {
    // Given
    renderResourceActionsCell({
      resource: makeResource({
        triage: makeTriageSummary({ hasVisibleNote: true }),
      }),
      onTriageUpdateAction: vi.fn(),
      onTriageNoteLoadAction: vi.fn(),
    });

    // Then
    expect(screen.getByRole("button", { name: "Open note" })).toBeEnabled();
    expect(screen.queryByText("Sensitive note body")).not.toBeInTheDocument();
    expect(screen.queryByText(/author/i)).not.toBeInTheDocument();
    expect(screen.queryByText(/timestamp/i)).not.toBeInTheDocument();
  });

  it("should disable Add Triage Note when no update handler is wired", () => {
    // Given
    renderResourceActionsCell({
      resource: makeResource({
        triage: makeTriageSummary({ hasVisibleNote: false }),
      }),
    });

    // Then
    expect(
      screen.getByRole("button", { name: "Add Triage Note" }),
    ).toBeDisabled();
  });

  it("should enable Add Triage Note when an update handler is wired", () => {
    // Given
    renderResourceActionsCell({
      resource: makeResource({
        triage: makeTriageSummary({ hasVisibleNote: false }),
      }),
      onTriageUpdateAction: vi.fn(),
    });

    // Then
    expect(
      screen.getByRole("button", { name: "Add Triage Note" }),
    ).toBeEnabled();
  });

  it("should enable Add Triage Note for Cloud-only rows so users can open the billing upsell modal", () => {
    // Given
    renderResourceActionsCell({
      resource: makeResource({
        triage: makeTriageSummary({
          canEdit: false,
          hasVisibleNote: false,
          disabledReason: FINDING_TRIAGE_DISABLED_REASON.CLOUD_ONLY,
        }),
      }),
    });

    // Then
    expect(
      screen.getByRole("button", { name: "Add Triage Note" }),
    ).toBeEnabled();
  });

  it("should disable editable triage control when no update handler is wired", () => {
    // Given
    const columns = getColumnFindingResources({
      rowSelection: {},
      selectableRowCount: 1,
    });
    const triageColumn = columns.find(
      (col) => (col as { id?: string }).id === "triage",
    );
    if (!triageColumn?.cell) {
      throw new Error("triage column not found");
    }
    const CellComponent = triageColumn.cell as (props: {
      row: { original: FindingResourceRow };
    }) => ReactNode;

    // When
    render(
      <div>
        {CellComponent({
          row: {
            original: makeResource({
              triage: makeTriageSummary({ canEdit: true }),
            }),
          },
        })}
      </div>,
    );

    // Then
    expect(
      screen.getByRole("button", { name: "Triage status" }),
    ).toBeDisabled();
    expect(screen.getByText(EDITING_UNAVAILABLE_COPY)).toBeInTheDocument();
  });

  it("should keep the compact Triage label on resource cells for headerless nested rows", () => {
    // Given
    const columns = getColumnFindingResources({
      rowSelection: {},
      selectableRowCount: 1,
    });
    const triageColumn = columns.find(
      (col) => (col as { id?: string }).id === "triage",
    );
    if (!triageColumn?.cell) {
      throw new Error("triage column not found");
    }
    const CellComponent = triageColumn.cell as (props: {
      row: { original: FindingResourceRow };
    }) => ReactNode;

    // When
    render(
      <div>
        {CellComponent({
          row: {
            original: makeResource({ triage: makeTriageSummary() }),
          },
        })}
      </div>,
    );

    // Then — expanded finding-group rows render without a header row, so the
    // cell itself must carry the label, like Service/Region/Last seen do.
    expect(screen.getByText("Triage")).toBeInTheDocument();
  });

  it("should disable non-paying Cloud triage control with only-in-Cloud tooltip copy", () => {
    // Given
    const columns = getColumnFindingResources({
      rowSelection: {},
      selectableRowCount: 1,
    });
    const triageColumn = columns.find(
      (col) => (col as { id?: string }).id === "triage",
    );
    if (!triageColumn?.cell) {
      throw new Error("triage column not found");
    }
    const CellComponent = triageColumn.cell as (props: {
      row: { original: FindingResourceRow };
    }) => ReactNode;

    // When
    render(
      <div>
        {CellComponent({
          row: {
            original: makeResource({
              triage: makeTriageSummary({
                canEdit: false,
                disabledReason: FINDING_TRIAGE_DISABLED_REASON.CLOUD_ONLY,
              }),
            }),
          },
        })}
      </div>,
    );

    // Then
    expect(
      screen.getByRole("button", { name: "Triage status" }),
    ).toBeDisabled();
    expect(screen.getByText(CLOUD_ONLY_TOOLTIP_COPY)).toBeInTheDocument();
  });

  it("should open Send to Jira modal with finding UUID directly", async () => {
    // Given
    const user = userEvent.setup();

    const columns = getColumnFindingResources({
      rowSelection: {},
      selectableRowCount: 1,
    });

    const actionColumn = columns.find(
      (col) => (col as { id?: string }).id === "actions",
    );
    if (!actionColumn?.cell) {
      throw new Error("actions column not found");
    }

    const CellComponent = actionColumn.cell as (props: {
      row: { original: FindingResourceRow };
    }) => ReactNode;

    render(
      <div>
        {CellComponent({
          row: {
            original: makeResource({
              findingId: "real-finding-uuid",
            }),
          },
        })}
      </div>,
    );

    // When
    await user.click(screen.getByRole("button", { name: "Send to Jira" }));

    // Then
    expect(screen.getByTestId("jira-modal")).toHaveAttribute(
      "data-finding-id",
      "real-finding-uuid",
    );
    expect(screen.getByTestId("jira-modal")).toHaveAttribute(
      "data-open",
      "true",
    );
  });
});
