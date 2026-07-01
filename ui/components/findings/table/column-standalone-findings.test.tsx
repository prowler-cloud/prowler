import { render, screen } from "@testing-library/react";
import type { ReactNode } from "react";
import { describe, expect, it, vi } from "vitest";

vi.mock("next/navigation", () => ({
  useRouter: () => ({ refresh: vi.fn() }),
}));

vi.mock("@/components/findings/mute-findings-modal", () => ({
  MuteFindingsModal: () => null,
}));

vi.mock("@/components/findings/send-to-jira-modal", () => ({
  SendToJiraModal: () => null,
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

vi.mock("@/components/shadcn/spinner/spinner", () => ({
  Spinner: () => null,
}));

vi.mock("@/components/ui/entities", () => ({
  DateWithTime: ({ dateTime }: { dateTime: string | null }) => (
    <time>{dateTime ?? "-"}</time>
  ),
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
    isMuted: false,
    canEdit: true,
    billingHref: "https://prowler.com/pricing",
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
  it("should render Triage and Actions as the last visible data columns without Notes", () => {
    // Given
    const columns = getStandaloneFindingColumns({ includeUpdatedAt: true });

    // When
    const columnIds = columns.map(
      (column) =>
        (column as { id?: string; accessorKey?: string }).id ??
        (column as { id?: string; accessorKey?: string }).accessorKey,
    );

    // Then
    expect(columnIds.slice(-2)).toEqual(["triage", "actions"]);
    expect(columnIds).not.toContain("notes");
    expect(
      (columns.at(-1) as { id?: string; size?: number } | undefined)?.size,
    ).toBe(56);
  });

  it("should render standalone finding triage status and note action from DTOs", () => {
    // Given
    const columns = getStandaloneFindingColumns({
      onTriageUpdateAction: vi.fn(),
    });
    const triageColumn = columns.find(
      (col) => (col as { id?: string }).id === "triage",
    );
    const actionsColumn = columns.find(
      (col) => (col as { id?: string }).id === "actions",
    );
    if (!triageColumn?.cell || !actionsColumn?.cell) {
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
    const ActionsCell = actionsColumn.cell as (props: {
      row: { original: FindingProps };
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
      screen.getByRole("button", { name: /triage status/i }),
    ).toHaveTextContent("Remediating");
    expect(
      screen.getByRole("button", { name: "Add Triage Note" }),
    ).toBeInTheDocument();
  });

  it("should keep standalone finding region on a single truncated line", () => {
    // Given
    const columns = getStandaloneFindingColumns();
    const regionColumn = columns.find(
      (col) =>
        (col as { accessorKey?: string }).accessorKey === "region" ||
        (col as { id?: string }).id === "region",
    );
    if (!regionColumn?.cell) {
      throw new Error("region column not found");
    }
    const RegionCell = regionColumn.cell as (props: {
      row: { original: FindingProps };
    }) => ReactNode;
    const finding = makeFinding({
      relationships: {
        resources: {
          data: [{ type: "resources", id: "resource-1" }],
        },
        scan: {
          data: { type: "scans", id: "scan-1" },
          attributes: {
            name: "scan-1",
            trigger: "manual",
            state: "completed",
            unique_resource_count: 1,
            progress: 100,
            scanner_args: { checks_to_execute: [] },
            duration: 1,
            started_at: "2024-01-01T00:00:00Z",
            inserted_at: "2024-01-01T00:00:00Z",
            completed_at: "2024-01-01T00:00:00Z",
            scheduled_at: null,
            next_scan_at: "2024-01-02T00:00:00Z",
          },
        },
        resource: {
          data: [{ type: "resources", id: "resource-1" }],
          id: "resource-1",
          attributes: {
            uid: "resource-uid-1",
            name: "resource-1",
            region: "ap-southeast-2",
            service: "s3",
            tags: {},
            type: "bucket",
            inserted_at: "2024-01-01T00:00:00Z",
            updated_at: "2024-01-02T00:00:00Z",
            details: null,
            partition: null,
          },
          relationships: {
            provider: {
              data: { type: "providers", id: "provider-1" },
            },
            findings: {
              meta: { count: 1 },
              data: [{ type: "findings", id: "finding-1" }],
            },
          },
          links: { self: "/resources/resource-1" },
        },
        provider: {
          data: { type: "providers", id: "provider-1" },
          attributes: {
            provider: "aws",
            uid: "123456789012",
            alias: "production",
            connection: {
              connected: true,
              last_checked_at: "2024-01-01T00:00:00Z",
            },
            inserted_at: "2024-01-01T00:00:00Z",
            updated_at: "2024-01-01T00:00:00Z",
          },
          relationships: {
            secret: {
              data: { type: "provider-secrets", id: "secret-1" },
            },
          },
          links: { self: "/providers/provider-1" },
        },
      },
    });

    // When
    render(<div>{RegionCell({ row: { original: finding } })}</div>);

    // Then
    expect(screen.getByText("ap-southeast-2").parentElement).toHaveClass(
      "truncate",
      "whitespace-nowrap",
    );
  });
});
