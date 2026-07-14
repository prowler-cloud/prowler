import { render, screen } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";

import { SCAN_JOBS_TAB, type ScanProps } from "@/types";
import { SCAN_SCHEDULE_CAPABILITY } from "@/types/schedules";

import { ScanJobsTable } from "./scan-jobs-table";

const { getScanJobsColumnsMock } = vi.hoisted(() => ({
  getScanJobsColumnsMock: vi.fn((_options: unknown) => []),
}));

vi.mock("@/components/shadcn/table", () => ({
  DataTable: ({ data }: { data: ScanProps[] }) => (
    <div data-testid="scan-jobs-data-table">{data.length}</div>
  ),
}));

vi.mock("./scan-jobs-columns", () => ({
  getScanJobsColumns: (options: unknown) => getScanJobsColumnsMock(options),
}));

vi.mock("../auto-refresh", () => ({
  AutoRefresh: ({ hasExecutingScan }: { hasExecutingScan: boolean }) => (
    <div data-testid="scan-jobs-auto-refresh">{String(hasExecutingScan)}</div>
  ),
}));

vi.mock("../no-scans-empty-state", () => ({
  NoScansEmptyState: ({ tab }: { tab: string }) => (
    <div data-testid="no-scans-empty-state">{tab}</div>
  ),
}));

const makeScan = (state: ScanProps["attributes"]["state"]): ScanProps => ({
  type: "scans",
  id: `scan-${state}`,
  attributes: {
    name: "Production scan",
    trigger: "manual",
    state,
    unique_resource_count: 0,
    progress: 100,
    scanner_args: null,
    duration: 0,
    started_at: "",
    inserted_at: "",
    completed_at: "",
    scheduled_at: "",
    next_scan_at: "",
  },
  relationships: {
    provider: { data: { type: "providers", id: "provider-1" } },
    task: { data: { type: "tasks", id: "task-1" } },
  },
});

describe("ScanJobsTable", () => {
  it("enables auto refresh while queued or executing scans are visible", () => {
    render(
      <ScanJobsTable
        data={[makeScan("available"), makeScan("completed")]}
        tab={SCAN_JOBS_TAB.ACTIVE}
      />,
    );

    expect(screen.getByTestId("scan-jobs-auto-refresh")).toHaveTextContent(
      "true",
    );
  });

  it("disables auto refresh when visible scans are not running", () => {
    render(
      <ScanJobsTable
        data={[makeScan("completed"), makeScan("failed")]}
        tab={SCAN_JOBS_TAB.COMPLETED}
      />,
    );

    expect(screen.getByTestId("scan-jobs-auto-refresh")).toHaveTextContent(
      "false",
    );
  });

  it("renders the empty state when there are no scans and no filters applied", () => {
    render(<ScanJobsTable data={[]} tab={SCAN_JOBS_TAB.ACTIVE} />);

    expect(screen.getByTestId("no-scans-empty-state")).toHaveTextContent(
      SCAN_JOBS_TAB.ACTIVE,
    );
    expect(
      screen.queryByTestId("scan-jobs-data-table"),
    ).not.toBeInTheDocument();
  });

  it("falls back to the data table when there are no scans but filters are applied", () => {
    render(<ScanJobsTable data={[]} tab={SCAN_JOBS_TAB.ACTIVE} hasFilters />);

    expect(screen.getByTestId("scan-jobs-data-table")).toBeInTheDocument();
    expect(
      screen.queryByTestId("no-scans-empty-state"),
    ).not.toBeInTheDocument();
  });

  it("passes scan schedule capability to scan job columns", () => {
    render(
      <ScanJobsTable
        data={[]}
        tab={SCAN_JOBS_TAB.ACTIVE}
        hasFilters
        scanScheduleCapability={SCAN_SCHEDULE_CAPABILITY.MANUAL_ONLY}
      />,
    );

    expect(getScanJobsColumnsMock).toHaveBeenCalledWith({
      tab: SCAN_JOBS_TAB.ACTIVE,
      capability: SCAN_SCHEDULE_CAPABILITY.MANUAL_ONLY,
    });
  });
});
