import { render, screen } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";

import type { ScanProps } from "@/types";

import { SCAN_JOBS_TAB } from "../../scans-table.utils";
import { ScanJobsTable } from "./scan-jobs-table";

vi.mock("@/components/ui/table", () => ({
  DataTable: ({ data }: { data: ScanProps[] }) => (
    <div data-testid="scan-jobs-data-table">{data.length}</div>
  ),
}));

vi.mock("./scan-jobs-columns", () => ({
  getScanJobsColumns: () => [],
}));

vi.mock("../../auto-refresh", () => ({
  AutoRefresh: ({ hasExecutingScan }: { hasExecutingScan: boolean }) => (
    <div data-testid="scan-jobs-auto-refresh">{String(hasExecutingScan)}</div>
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

  it("shows documentation helper in the imported findings tab", () => {
    render(<ScanJobsTable data={[]} tab={SCAN_JOBS_TAB.IMPORTED} />);

    expect(
      screen.getByText("There are no scans with imported findings yet"),
    ).toBeInTheDocument();
    const docsLink = screen.getByRole("link", {
      name: /import findings guide/i,
    });

    expect(docsLink).toHaveAttribute(
      "href",
      "https://docs.prowler.com/user-guide/tutorials/prowler-app-import-findings",
    );
  });
});
