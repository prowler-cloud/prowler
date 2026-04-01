import { flexRender } from "@tanstack/react-table";
import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import type { ReactNode } from "react";
import { beforeEach, describe, expect, it, vi } from "vitest";

import type { AttackPathScan } from "@/types/attack-paths";

import { ScanListTable } from "./scan-list-table";

const { pushMock, navigationState } = vi.hoisted(() => ({
  pushMock: vi.fn(),
  navigationState: {
    pathname: "/attack-paths",
    searchParams: new URLSearchParams("scanPage=1&scanPageSize=5"),
  },
}));

vi.mock("next/navigation", () => ({
  usePathname: () => navigationState.pathname,
  useRouter: () => ({
    push: pushMock,
  }),
  useSearchParams: () => navigationState.searchParams,
}));

vi.mock("@/components/ui/entities/entity-info", () => ({
  EntityInfo: ({
    entityAlias,
    entityId,
  }: {
    entityAlias?: string;
    entityId?: string;
  }) => <div>{entityAlias ?? entityId}</div>,
}));

vi.mock("@/components/ui/entities/date-with-time", () => ({
  DateWithTime: ({ dateTime }: { dateTime: string }) => <span>{dateTime}</span>,
}));

vi.mock("@/components/ui/table", () => ({
  DataTableColumnHeader: ({ title }: { title: string }) => <span>{title}</span>,
  DataTable: ({
    columns,
    data,
    metadata,
    controlledPage,
  }: {
    columns: Array<{
      id?: string;
      header?:
        | string
        | ((context: { column: { getCanSort: () => boolean } }) => ReactNode);
      cell?: (context: { row: { original: AttackPathScan } }) => ReactNode;
    }>;
    data: AttackPathScan[];
    metadata: {
      pagination: {
        count: number;
        pages: number;
      };
    };
    controlledPage: number;
  }) => (
    <div>
      <span>{metadata.pagination.count} Total Entries</span>
      <span>
        Page {controlledPage} of {metadata.pagination.pages}
      </span>
      <table>
        <thead>
          <tr>
            {columns.map((column, index) => (
              <th key={column.id ?? index}>
                {typeof column.header === "function"
                  ? flexRender(column.header, {
                      column: { getCanSort: () => false },
                    })
                  : column.header}
              </th>
            ))}
          </tr>
        </thead>
        <tbody>
          {data.map((row) => (
            <tr key={row.id}>
              {columns.map((column, index) => (
                <td key={column.id ?? index}>
                  {column.cell
                    ? flexRender(column.cell, { row: { original: row } })
                    : null}
                </td>
              ))}
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  ),
}));

const createScan = (id: number): AttackPathScan => ({
  type: "attack-paths-scans",
  id: `scan-${id}`,
  attributes: {
    state: "completed",
    progress: 100,
    graph_data_ready: true,
    provider_alias: `Provider ${id}`,
    provider_type: "aws",
    provider_uid: `1234567890${id}`,
    inserted_at: "2026-03-11T10:00:00Z",
    started_at: "2026-03-11T10:00:00Z",
    completed_at: "2026-03-11T10:05:00Z",
    duration: 300,
  },
  relationships: {
    provider: {
      data: {
        type: "providers",
        id: `provider-${id}`,
      },
    },
    scan: {
      data: {
        type: "scans",
        id: `base-scan-${id}`,
      },
    },
    task: {
      data: {
        type: "tasks",
        id: `task-${id}`,
      },
    },
  },
});

describe("ScanListTable", () => {
  beforeEach(() => {
    pushMock.mockReset();
    navigationState.searchParams = new URLSearchParams(
      "scanPage=1&scanPageSize=5",
    );
  });

  it("uses the shared data table chrome and preserves query params when selecting a scan", async () => {
    const user = userEvent.setup();

    render(
      <ScanListTable
        scans={Array.from({ length: 12 }, (_, index) => createScan(index + 1))}
      />,
    );

    expect(screen.getByText("12 Total Entries")).toBeInTheDocument();
    expect(screen.getByText("Page 1 of 3")).toBeInTheDocument();

    await user.click(screen.getAllByRole("button", { name: "Select scan" })[0]);

    expect(pushMock).toHaveBeenCalledWith(
      "/attack-paths?scanPage=1&scanPageSize=5&scanId=scan-1",
    );
  });

  it("enables the select button for a failed scan when graph data is ready", async () => {
    const user = userEvent.setup();
    const failedScan: AttackPathScan = {
      ...createScan(1),
      attributes: {
        ...createScan(1).attributes,
        state: "failed",
        graph_data_ready: true,
      },
    };

    render(<ScanListTable scans={[failedScan]} />);

    const button = screen.getByRole("button", { name: "Select scan" });
    expect(button).toBeEnabled();
    expect(button).toHaveTextContent("Select");

    await user.click(button);

    expect(pushMock).toHaveBeenCalledWith(
      "/attack-paths?scanPage=1&scanPageSize=5&scanId=scan-1",
    );
  });

  it("disables the select button for a failed scan when graph data is not ready", () => {
    const failedScan: AttackPathScan = {
      ...createScan(1),
      attributes: {
        ...createScan(1).attributes,
        state: "failed",
        graph_data_ready: false,
      },
    };

    render(<ScanListTable scans={[failedScan]} />);

    const button = screen.getByRole("button", { name: "Select scan" });
    expect(button).toBeDisabled();
    expect(button).toHaveTextContent("Failed");
  });
});
