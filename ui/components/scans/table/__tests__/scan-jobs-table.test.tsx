import { render, screen } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";

import { SCAN_JOBS_TAB, type ScanProps } from "@/types";

import { ScanJobsTable } from "../scan-jobs-table";

// Mock DataTable to a minimal table that applies getRowAttributes per row, so we can
// assert the view-first-scan "in-progress" anchor lands on the right row/tab.
vi.mock("@/components/ui/table", () => ({
  DataTable: ({
    data,
    getRowAttributes,
  }: {
    data?: ScanProps[];
    getRowAttributes?: (row: {
      index: number;
      original: ScanProps;
    }) => Record<string, string | undefined>;
  }) => (
    <table>
      <tbody>
        {(data ?? []).map((original, index) => (
          <tr
            key={index}
            data-testid={`row-${index}`}
            {...getRowAttributes?.({ index, original })}
          >
            <td>scan</td>
          </tr>
        ))}
      </tbody>
    </table>
  ),
}));

// AutoRefresh polls via router on a timer; irrelevant to anchor placement.
vi.mock("../../auto-refresh", () => ({ AutoRefresh: () => null }));
vi.mock("../scan-jobs-columns", () => ({ getScanJobsColumns: () => [] }));
// Not rendered (data is non-empty), but mocked so its server/auth import chain
// doesn't load under vitest.
vi.mock("../../no-scans-empty-state", () => ({
  NoScansEmptyState: () => null,
}));

const scan = (state: string): ScanProps =>
  ({ attributes: { state } }) as unknown as ScanProps;

describe("ScanJobsTable in-progress tour anchor", () => {
  it("anchors the tour to the first row on the active (In Progress) tab", () => {
    render(
      <ScanJobsTable
        data={[scan("executing"), scan("executing")]}
        tab={SCAN_JOBS_TAB.ACTIVE}
      />,
    );

    // Only the first active-tab row carries the anchor — driver.js resolves the
    // running scan from it.
    expect(screen.getByTestId("row-0")).toHaveAttribute(
      "data-tour-id",
      "view-first-scan-in-progress",
    );
    expect(screen.getByTestId("row-1")).not.toHaveAttribute("data-tour-id");
  });

  it("never anchors on a non-active tab (no running scan to point at)", () => {
    render(
      <ScanJobsTable
        data={[scan("completed")]}
        tab={SCAN_JOBS_TAB.COMPLETED}
      />,
    );

    expect(screen.getByTestId("row-0")).not.toHaveAttribute("data-tour-id");
  });
});
