import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import type { InputHTMLAttributes, ReactNode } from "react";
import { describe, expect, it, vi } from "vitest";

vi.mock("@/components/shadcn", () => ({
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

import { getColumnFindingResources } from "./column-finding-resources";

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
