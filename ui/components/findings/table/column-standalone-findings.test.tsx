import { render, screen } from "@testing-library/react";
import type { ReactNode } from "react";
import { describe, expect, it, vi } from "vitest";

vi.mock("@/components/ui/entities", () => ({
  DateWithTime: () => null,
  EntityInfo: () => null,
}));

vi.mock("@/components/ui/table", () => ({
  DataTableColumnHeader: ({ title }: { title: string }) => <span>{title}</span>,
  SeverityBadge: ({ severity }: { severity: string }) => (
    <span>{severity}</span>
  ),
  StatusFindingBadge: ({ status }: { status: string }) => <span>{status}</span>,
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
}));

vi.mock("@/components/shadcn/tooltip", () => ({
  Tooltip: ({ children }: { children: ReactNode }) => <>{children}</>,
  TooltipContent: ({ children }: { children: ReactNode }) => (
    <span>{children}</span>
  ),
  TooltipTrigger: ({ children }: { children: ReactNode }) => <>{children}</>,
}));

vi.mock("@/lib/region-flags", () => ({
  getRegionFlag: () => "",
}));

vi.mock("./finding-detail-drawer", () => ({
  FindingDetailDrawer: ({ trigger }: { trigger: ReactNode }) => <>{trigger}</>,
}));

vi.mock("./notification-indicator", () => ({
  DeltaValues: { NEW: "new", CHANGED: "changed", NONE: "none" },
  NotificationIndicator: () => null,
}));

vi.mock("./provider-icon-cell", () => ({
  ProviderIconCell: () => null,
}));

import type { FindingProps } from "@/types";
import {
  FINDING_TRIAGE_STATUS,
  type FindingTriageSummary,
} from "@/types/findings-triage";

import { getStandaloneFindingColumns } from "./column-standalone-findings";

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
    billingHref: "/billing",
    mutelistShortcutStatuses: [
      FINDING_TRIAGE_STATUS.RISK_ACCEPTED,
      FINDING_TRIAGE_STATUS.FALSE_POSITIVE,
    ],
    ...overrides,
  };
}

function makeFinding(overrides?: Partial<FindingProps>): FindingProps {
  return {
    type: "findings",
    id: "finding-1",
    triage: makeTriageSummary(),
    attributes: {
      uid: "prowler-finding-uid-1",
      status: "FAIL",
      severity: "critical",
      check_metadata: { checktitle: "S3 public access", servicename: "s3" },
    },
    relationships: {},
    ...overrides,
  } as unknown as FindingProps;
}

describe("column-standalone-findings", () => {
  it("should render Triage and Notes as the last visible data columns", () => {
    // Given
    const columns = getStandaloneFindingColumns({ includeUpdatedAt: true });

    // When
    const columnIds = columns.map(
      (column) =>
        (column as { id?: string; accessorKey?: string }).id ??
        (column as { id?: string; accessorKey?: string }).accessorKey,
    );

    // Then
    expect(columnIds.slice(-2)).toEqual(["triage", "notes"]);
  });

  it("should render standalone finding triage status and note empty state from DTOs", () => {
    // Given
    const columns = getStandaloneFindingColumns();
    const triageColumn = columns.find(
      (col) => (col as { id?: string }).id === "triage",
    );
    const notesColumn = columns.find(
      (col) => (col as { id?: string }).id === "notes",
    );
    if (!triageColumn?.cell || !notesColumn?.cell) {
      throw new Error("triage columns not found");
    }
    const finding = makeFinding({
      triage: makeTriageSummary({
        status: FINDING_TRIAGE_STATUS.REMEDIATING,
        label: "Remediating",
        hasVisibleNote: false,
      }),
    });
    const TriageCell = triageColumn.cell as (props: {
      row: { original: FindingProps };
    }) => ReactNode;
    const NotesCell = notesColumn.cell as (props: {
      row: { original: FindingProps };
    }) => ReactNode;

    // When
    render(
      <div>
        {TriageCell({ row: { original: finding } })}
        {NotesCell({ row: { original: finding } })}
      </div>,
    );

    // Then
    expect(
      screen.getByRole("button", { name: /triage status/i }),
    ).toHaveTextContent("Remediating");
    expect(
      screen.getByRole("button", { name: "Add note" }),
    ).toBeInTheDocument();
  });
});
