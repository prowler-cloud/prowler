import type { CellContext, HeaderContext } from "@tanstack/react-table";
import { render, screen } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";

import type { ScanProps } from "@/types";

vi.mock("@/components/shadcn", () => ({
  Badge: ({ children }: { children: React.ReactNode }) => (
    <span>{children}</span>
  ),
  Progress: () => <div />,
}));

vi.mock("@/components/ui/entities", () => ({
  DateWithTime: () => <time />,
  EntityInfo: ({
    entityAlias,
    entityId,
    idLabel,
  }: {
    entityAlias?: string;
    entityId?: string;
    idLabel?: string;
  }) => (
    <div>
      <span>{entityAlias}</span>
      <span>
        {idLabel}: {entityId}
      </span>
    </div>
  ),
}));

vi.mock("@/components/ui/custom", () => ({
  TableLink: ({
    href,
    isDisabled,
    label,
  }: {
    href: string;
    isDisabled?: boolean;
    label: string;
  }) => (isDisabled ? <span>{label}</span> : <a href={href}>{label}</a>),
}));

vi.mock("@/components/ui/table", () => ({
  DataTableColumnHeader: ({ title }: { title: string }) => <span>{title}</span>,
}));

vi.mock("./scan-jobs-row-actions", () => ({
  ScanJobsRowActions: () => <button type="button" />,
}));

import { SCAN_JOBS_TAB, type ScanJobsTab } from "@/types";

import { getScanJobsColumns } from "./scan-jobs-columns";

const getColumnIds = (tab: ScanJobsTab) =>
  getScanJobsColumns({ tab }).map((column) => column.id);

const makeCompletedScan = (): ScanProps => ({
  type: "scans",
  id: "scan-1",
  attributes: {
    name: "Production scan",
    trigger: "manual",
    state: "completed",
    unique_resource_count: 7,
    progress: 100,
    scanner_args: null,
    duration: 73,
    started_at: "2026-01-01T10:00:00Z",
    inserted_at: "2026-01-01T10:00:00Z",
    completed_at: "2026-01-01T10:05:00Z",
    scheduled_at: "",
    next_scan_at: "",
  },
  relationships: {
    provider: { data: { type: "providers", id: "provider-1" } },
    task: { data: { type: "tasks", id: "task-1" } },
  },
});

const makeScheduledScan = (): ScanProps => ({
  ...makeCompletedScan(),
  attributes: {
    ...makeCompletedScan().attributes,
    trigger: "scheduled",
    state: "scheduled",
    scheduled_at: "2026-01-01T10:00:00Z",
    next_scan_at: "2026-01-02T10:00:00Z",
  },
});

const renderCell = (
  columnId: string,
  scan: ScanProps,
  tab: ScanJobsTab = SCAN_JOBS_TAB.COMPLETED,
) => {
  const column = getScanJobsColumns({
    tab,
  }).find((item) => item.id === columnId);
  const cell = column?.cell as
    | ((context: CellContext<ScanProps, unknown>) => React.ReactNode)
    | undefined;

  if (!cell) throw new Error(`Column ${columnId} does not define a cell`);

  render(
    <>{cell({ row: { original: scan } } as CellContext<ScanProps, unknown>)}</>,
  );
};

const renderHeader = (tab: ScanJobsTab, columnId: string) => {
  const column = getScanJobsColumns({ tab }).find(
    (item) => item.id === columnId,
  );
  const header = column?.header;

  if (typeof header !== "function") {
    throw new Error(`Column ${columnId} does not define a header`);
  }

  render(<>{header({ column: {} } as HeaderContext<ScanProps, unknown>)}</>);
};

describe("getScanJobsColumns", () => {
  it("uses the expected columns for each scan tab", () => {
    expect(getColumnIds(SCAN_JOBS_TAB.ACTIVE)).toEqual([
      "account",
      "scanInfo",
      "progress",
      "scanSchedule",
      "launched",
      "actions",
    ]);
    expect(getColumnIds(SCAN_JOBS_TAB.COMPLETED)).toEqual([
      "account",
      "scanInfo",
      "resources",
      "duration",
      "status",
      "scanSchedule",
      "scanDate",
      "actions",
    ]);
    expect(getColumnIds(SCAN_JOBS_TAB.SCHEDULED)).toEqual([
      "account",
      "scanInfo",
      "scanSchedule",
      "actions",
    ]);
  });

  it("labels the scan info column as Info in scan tables", () => {
    renderHeader(SCAN_JOBS_TAB.ACTIVE, "scanInfo");
    renderHeader(SCAN_JOBS_TAB.COMPLETED, "scanInfo");

    expect(screen.getAllByText("Info")).toHaveLength(2);
    expect(screen.queryByText("Alias")).not.toBeInTheDocument();
    expect(screen.queryByText("Scan Note")).not.toBeInTheDocument();
  });

  it("renders the scan alias with the scan id underneath", () => {
    renderCell("scanInfo", makeCompletedScan());

    expect(screen.getByText("Production scan")).toBeInTheDocument();
    expect(screen.getByText("ID: scan-1")).toBeInTheDocument();
  });

  it("renders the completed duration column", () => {
    renderCell("duration", makeCompletedScan());

    expect(screen.getByText("1 min 13 sec")).toBeInTheDocument();
  });

  it("labels the completed scan schedule column as Type", () => {
    renderHeader(SCAN_JOBS_TAB.COMPLETED, "scanSchedule");

    expect(screen.getByText("Type")).toBeInTheDocument();
    expect(screen.queryByText("Schedule")).not.toBeInTheDocument();
  });

  it("keeps the scheduled column without repeating the scheduled label in each row", () => {
    renderHeader(SCAN_JOBS_TAB.SCHEDULED, "scanSchedule");
    renderCell("scanSchedule", makeScheduledScan(), SCAN_JOBS_TAB.SCHEDULED);

    expect(screen.getByText("Schedule")).toBeInTheDocument();
    expect(screen.queryByText("Scheduled")).not.toBeInTheDocument();
  });
});
