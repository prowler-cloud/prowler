import type { CellContext, HeaderContext } from "@tanstack/react-table";
import { render, screen } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";

import type { ScanProps } from "@/types";

vi.mock("@/components/shadcn", () => ({
  Badge: ({ children }: { children: React.ReactNode }) => (
    <span>{children}</span>
  ),
  Progress: () => <div />,
  Tooltip: ({ children }: { children: React.ReactNode }) => <>{children}</>,
  TooltipContent: ({ children }: { children: React.ReactNode }) => (
    <span>{children}</span>
  ),
  TooltipTrigger: ({ children }: { children: React.ReactNode }) => (
    <>{children}</>
  ),
}));

vi.mock("@/components/ui/entities", () => ({
  DateWithTime: () => <time />,
  EntityInfo: () => <span />,
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

import { SCAN_JOBS_TAB, type ScanJobsTab } from "../../scans-table.utils";
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

const renderCell = (columnId: string, scan: ScanProps) => {
  const column = getScanJobsColumns({
    tab: SCAN_JOBS_TAB.COMPLETED,
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
      "scanNote",
      "progress",
      "scanTime",
      "scanSchedule",
      "launched",
      "actions",
    ]);
    expect(getColumnIds(SCAN_JOBS_TAB.COMPLETED)).toEqual([
      "account",
      "scanNote",
      "resources",
      "findings",
      "status",
      "scanSchedule",
      "scanDate",
      "actions",
    ]);
    expect(getColumnIds(SCAN_JOBS_TAB.SCHEDULED)).toEqual([
      "account",
      "scanSchedule",
      "nextScan",
      "actions",
    ]);
  });

  it("labels the scan alias column as Alias in scan tables", () => {
    renderHeader(SCAN_JOBS_TAB.ACTIVE, "scanNote");
    renderHeader(SCAN_JOBS_TAB.COMPLETED, "scanNote");

    expect(screen.getAllByText("Alias")).toHaveLength(2);
    expect(screen.queryByText("Scan Note")).not.toBeInTheDocument();
  });

  it("renders the completed findings column as a findings link", () => {
    renderCell("findings", makeCompletedScan());

    const link = screen.getByRole("link", { name: /view findings/i });

    expect(link).toHaveAttribute(
      "href",
      "/findings?filter[scan]=scan-1&filter[inserted_at]=2026-01-01&filter[status__in]=FAIL",
    );
  });
});
