import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import type {
  ButtonHTMLAttributes,
  InputHTMLAttributes,
  ReactNode,
} from "react";
import { describe, expect, it, vi } from "vitest";

vi.mock("@/components/shadcn", () => ({
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
  InfoField: () => null,
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
  SelectStatusDot: () => <span data-testid="select-status-dot" />,
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

vi.mock("@/components/ui/entities", () => ({
  DateWithTime: () => null,
}));

vi.mock("@/components/ui/entities/entity-info", () => ({
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

vi.mock("@/components/ui/table", () => ({
  SeverityBadge: ({ severity }: { severity: string }) => (
    <span>{severity}</span>
  ),
}));

vi.mock("@/components/ui/table/data-table-column-header", () => ({
  DataTableColumnHeader: ({ title }: { title: string }) => <span>{title}</span>,
}));

vi.mock("@/components/ui/table/status-finding-badge", () => ({
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
    hasPersistedStatus: true,
    canEdit: true,
    billingHref: "https://prowler.com/pricing",
    mutelistShortcutStatuses: [
      FINDING_TRIAGE_STATUS.RISK_ACCEPTED,
      FINDING_TRIAGE_STATUS.FALSE_POSITIVE,
    ],
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

describe("column-finding-resources", () => {
  it("should render Triage and Notes as the last visible data columns", () => {
    // Given
    const columns = getColumnFindingResources({
      rowSelection: {},
      selectableRowCount: 1,
    });

    // When
    const columnIds = columns.map(
      (column) =>
        (column as { id?: string; accessorKey?: string }).id ??
        (column as { id?: string; accessorKey?: string }).accessorKey,
    );

    // Then
    expect(columnIds.slice(-3)).toEqual(["actions", "triage", "notes"]);
  });

  it("should render the current triage status label", () => {
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
                status: FINDING_TRIAGE_STATUS.REMEDIATING,
                label: "Remediating",
              }),
            }),
          },
        })}
      </div>,
    );

    // Then
    expect(
      screen.getByRole("button", { name: /triage status/i }),
    ).toHaveTextContent("Remediating");
  });

  it("should render note presence only without exposing note preview metadata", () => {
    // Given
    const columns = getColumnFindingResources({
      rowSelection: {},
      selectableRowCount: 1,
    });
    const notesColumn = columns.find(
      (col) => (col as { id?: string }).id === "notes",
    );
    if (!notesColumn?.cell) {
      throw new Error("notes column not found");
    }
    const CellComponent = notesColumn.cell as (props: {
      row: { original: FindingResourceRow };
    }) => ReactNode;

    // When
    render(
      <div>
        {CellComponent({
          row: {
            original: makeResource({
              triage: makeTriageSummary({ hasVisibleNote: true }),
            }),
          },
        })}
      </div>,
    );

    // Then
    expect(screen.getByLabelText("Note exists")).toBeInTheDocument();
    expect(screen.queryByText("Sensitive note body")).not.toBeInTheDocument();
    expect(screen.queryByText(/author/i)).not.toBeInTheDocument();
    expect(screen.queryByText(/timestamp/i)).not.toBeInTheDocument();
  });

  it("should disable Add note when no update handler is wired", () => {
    // Given
    const columns = getColumnFindingResources({
      rowSelection: {},
      selectableRowCount: 1,
    });
    const notesColumn = columns.find(
      (col) => (col as { id?: string }).id === "notes",
    );
    if (!notesColumn?.cell) {
      throw new Error("notes column not found");
    }
    const CellComponent = notesColumn.cell as (props: {
      row: { original: FindingResourceRow };
    }) => ReactNode;

    // When
    render(
      <div>
        {CellComponent({
          row: {
            original: makeResource({
              triage: makeTriageSummary({ hasVisibleNote: false }),
            }),
          },
        })}
      </div>,
    );

    // Then
    expect(screen.getByRole("button", { name: "Add note" })).toBeDisabled();
  });

  it("should enable Add note when an update handler is wired", () => {
    // Given
    const columns = getColumnFindingResources({
      rowSelection: {},
      selectableRowCount: 1,
      onTriageUpdateAction: vi.fn(),
    });
    const notesColumn = columns.find(
      (col) => (col as { id?: string }).id === "notes",
    );
    if (!notesColumn?.cell) {
      throw new Error("notes column not found");
    }
    const CellComponent = notesColumn.cell as (props: {
      row: { original: FindingResourceRow };
    }) => ReactNode;

    // When
    render(
      <div>
        {CellComponent({
          row: {
            original: makeResource({
              triage: makeTriageSummary({ hasVisibleNote: false }),
            }),
          },
        })}
      </div>,
    );

    // Then
    expect(screen.getByRole("button", { name: "Add note" })).toBeEnabled();
  });

  it("should enable Add note for Cloud-only rows so users can open the billing upsell modal", () => {
    // Given
    const columns = getColumnFindingResources({
      rowSelection: {},
      selectableRowCount: 1,
    });
    const notesColumn = columns.find(
      (col) => (col as { id?: string }).id === "notes",
    );
    if (!notesColumn?.cell) {
      throw new Error("notes column not found");
    }
    const CellComponent = notesColumn.cell as (props: {
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
                hasVisibleNote: false,
                disabledReason: FINDING_TRIAGE_DISABLED_REASON.CLOUD_ONLY,
              }),
            }),
          },
        })}
      </div>,
    );

    // Then
    expect(screen.getByRole("button", { name: "Add note" })).toBeEnabled();
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
    expect(
      screen.getByText("Editing is currently unavailable."),
    ).toBeInTheDocument();
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
    expect(
      screen.getByText("This feature is only in Cloud."),
    ).toBeInTheDocument();
  });

  it("should pass delta to NotificationIndicator for resource rows", () => {
    const columns = getColumnFindingResources({
      rowSelection: {},
      selectableRowCount: 1,
    });

    const selectColumn = columns.find(
      (col) => (col as { id?: string }).id === "select",
    );
    if (!selectColumn?.cell) {
      throw new Error("select column not found");
    }

    const CellComponent = selectColumn.cell as (props: {
      row: {
        id: string;
        original: FindingResourceRow;
        toggleSelected: (selected: boolean) => void;
      };
    }) => ReactNode;

    render(
      <div>
        {CellComponent({
          row: {
            id: "0",
            original: makeResource(),
            toggleSelected: vi.fn(),
          },
        })}
      </div>,
    );

    expect(screen.getByLabelText("Select resource")).toBeInTheDocument();
    expect(notificationIndicatorMock).toHaveBeenCalledWith(
      expect.objectContaining({
        delta: "new",
        isMuted: false,
      }),
    );
  });

  it("should render the resource EntityInfo with resourceName as alias", () => {
    const columns = getColumnFindingResources({
      rowSelection: {},
      selectableRowCount: 1,
    });

    const resourceColumn = columns.find(
      (col) => (col as { id?: string }).id === "resource",
    );
    if (!resourceColumn?.cell) {
      throw new Error("resource column not found");
    }

    const CellComponent = resourceColumn.cell as (props: {
      row: { original: FindingResourceRow };
    }) => ReactNode;

    render(
      <div>
        {CellComponent({
          row: {
            original: makeResource(),
          },
        })}
      </div>,
    );

    expect(screen.getByText("my-bucket")).toBeInTheDocument();
    expect(screen.getByText("arn:aws:s3:::my-bucket")).toBeInTheDocument();
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
