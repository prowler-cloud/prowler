import { render, screen } from "@testing-library/react";
import type { ReactNode } from "react";
import { describe, expect, it, vi } from "vitest";

vi.mock("@/components/findings/table", () => ({
  DataTableRowActions: ({
    row,
    onTriageUpdateAction,
  }: {
    row: { original: ResourceFinding };
    onTriageUpdateAction?: unknown;
  }) => (
    <button disabled={!row.original.triage || !onTriageUpdateAction}>
      {row.original.triage ? "Add Triage Note" : "-"}
    </button>
  ),
  FindingTriageStatusCell: ({ triage }: { triage?: { label: string } }) =>
    triage ? (
      <button aria-label="Triage status">{triage.label}</button>
    ) : (
      <span>-</span>
    ),
}));

vi.mock("@/components/findings/table/notification-indicator", () => ({
  NotificationIndicator: () => null,
}));

vi.mock("@/components/shadcn", () => ({
  Checkbox: ({ "aria-label": ariaLabel }: { "aria-label"?: string }) => (
    <input type="checkbox" aria-label={ariaLabel} />
  ),
}));

vi.mock("@/components/shadcn/entities", () => ({
  DateWithTime: ({ dateTime }: { dateTime: string }) => <time>{dateTime}</time>,
}));

vi.mock("@/components/shadcn/table", () => ({
  DataTableColumnHeader: ({ title }: { title: string }) => <span>{title}</span>,
  SeverityBadge: ({ severity }: { severity: string }) => (
    <span>{severity}</span>
  ),
  StatusFindingBadge: ({ status }: { status: string }) => <span>{status}</span>,
}));

import {
  FINDING_TRIAGE_STATUS,
  type FindingTriageSummary,
} from "@/types/findings-triage";

import {
  getResourceFindingsColumns,
  type ResourceFinding,
} from "./resource-findings-columns";

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

function makeFinding(overrides?: Partial<ResourceFinding>): ResourceFinding {
  return {
    type: "findings",
    id: "finding-1",
    triage: makeTriageSummary(),
    attributes: {
      status: "FAIL",
      severity: "critical",
      muted: false,
      updated_at: "2026-03-30T10:05:00Z",
      check_metadata: {
        checktitle: "S3 public access",
      },
    },
    ...overrides,
  };
}

function getColumnIds(columns: ReturnType<typeof getResourceFindingsColumns>) {
  return columns.map(
    (column) =>
      (column as { id?: string; accessorKey?: string }).id ??
      (column as { id?: string; accessorKey?: string }).accessorKey,
  );
}

describe("resource-findings-columns", () => {
  it("should render Triage before actions without adding a Notes column", () => {
    // Given
    const columns = getResourceFindingsColumns({}, 1, vi.fn());

    // When
    const columnIds = getColumnIds(columns);

    // Then
    expect(columnIds.slice(-2)).toEqual(["triage", "actions"]);
    expect(columnIds).not.toContain("notes");
  });

  it("should render triage status and Add Triage Note action from the finding DTO", () => {
    // Given
    const columns = getResourceFindingsColumns(
      {},
      1,
      vi.fn(),
      vi.fn(),
      vi.fn(),
    );
    const triageColumn = columns.find(
      (col) => (col as { id?: string }).id === "triage",
    );
    const actionsColumn = columns.find(
      (col) => (col as { id?: string }).id === "actions",
    );
    if (!triageColumn?.cell || !actionsColumn?.cell) {
      throw new Error("triage/actions columns not found");
    }
    const finding = makeFinding({
      triage: makeTriageSummary({
        status: FINDING_TRIAGE_STATUS.REMEDIATING,
        label: "Remediating",
      }),
    });
    const TriageCell = triageColumn.cell as (props: {
      row: { original: ResourceFinding };
    }) => ReactNode;
    const ActionsCell = actionsColumn.cell as (props: {
      row: { original: ResourceFinding };
    }) => ReactNode;

    // When
    render(
      <div>
        {TriageCell({ row: { original: finding } })}
        {ActionsCell({ row: { original: finding } })}
      </div>,
    );

    // Then
    expect(
      screen.getByRole("button", { name: "Triage status" }),
    ).toHaveTextContent("Remediating");
    expect(
      screen.getByRole("button", { name: "Add Triage Note" }),
    ).toBeEnabled();
  });
});
