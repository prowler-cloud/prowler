import { describe, expect, it, vi } from "vitest";

vi.mock("@/components/shadcn", () => ({
  Badge: ({ children }: { children: React.ReactNode }) => (
    <span>{children}</span>
  ),
  Checkbox: () => <input type="checkbox" />,
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

vi.mock("@/components/ui/table", () => ({
  DataTableColumnHeader: ({ title }: { title: string }) => <span>{title}</span>,
}));

vi.mock("./scan-jobs-row-actions", () => ({
  ScanJobsRowActions: () => <button type="button" />,
}));

import { SCAN_JOBS_TAB, type ScanJobsTab } from "../../scans-table.utils";
import { getScanJobsColumns } from "./scan-jobs-columns";

const getColumnIds = (tab: ScanJobsTab) =>
  getScanJobsColumns({
    tab,
    rowSelection: {},
    selectableRowCount: 1,
  }).map((column) => column.id);

describe("getScanJobsColumns", () => {
  it("uses the expected columns for each scan tab", () => {
    expect(getColumnIds(SCAN_JOBS_TAB.ACTIVE)).toEqual([
      "select",
      "account",
      "scanNote",
      "progress",
      "scanTime",
      "scanSchedule",
      "launched",
      "actions",
    ]);
    expect(getColumnIds(SCAN_JOBS_TAB.COMPLETED)).toEqual([
      "select",
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
      "select",
      "account",
      "scanSchedule",
      "lastScan",
      "nextScan",
      "actions",
    ]);
  });
});
