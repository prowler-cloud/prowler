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

vi.mock("@/components/shadcn/tooltip", () => ({
  Tooltip: ({ children }: { children: ReactNode }) => <>{children}</>,
  TooltipTrigger: ({
    children,
  }: {
    children: ReactNode;
    asChild?: boolean;
  }) => <>{children}</>,
  TooltipContent: ({ children }: { children: ReactNode }) => (
    <span data-testid="tooltip-content">{children}</span>
  ),
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

    await user.click(screen.getAllByRole("radio", { name: "Select scan" })[0]);

    expect(pushMock).toHaveBeenCalledWith(
      "/attack-paths?scanPage=1&scanPageSize=5&scanId=scan-1",
    );
  });

  it("enables the radio button for a failed scan when graph data is ready", async () => {
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

    const radio = screen.getByRole("radio", { name: "Select scan" });
    expect(radio).toBeEnabled();
    expect(radio).toHaveAttribute("aria-checked", "false");

    await user.click(radio);

    expect(pushMock).toHaveBeenCalledWith(
      "/attack-paths?scanPage=1&scanPageSize=5&scanId=scan-1",
    );
  });

  it("disables the radio button for a failed scan when graph data is not ready", () => {
    const failedScan: AttackPathScan = {
      ...createScan(1),
      attributes: {
        ...createScan(1).attributes,
        state: "failed",
        graph_data_ready: false,
      },
    };

    render(<ScanListTable scans={[failedScan]} />);

    const radio = screen.getByRole("radio", { name: "Scan not available" });
    expect(radio).toBeDisabled();
  });

  it("shows a disabled radio button for a scheduled scan without graph data", () => {
    const scheduledScan: AttackPathScan = {
      ...createScan(1),
      attributes: {
        ...createScan(1).attributes,
        state: "scheduled",
        progress: 0,
        graph_data_ready: false,
        completed_at: null,
        duration: null,
      },
    };

    render(<ScanListTable scans={[scheduledScan]} />);

    const radio = screen.getByRole("radio", { name: "Scan not available" });
    expect(radio).toBeDisabled();
  });

  it("shows a disabled radio button for an executing scan without graph data", () => {
    const executingScan: AttackPathScan = {
      ...createScan(1),
      attributes: {
        ...createScan(1).attributes,
        state: "executing",
        progress: 45,
        graph_data_ready: false,
        completed_at: null,
        duration: null,
      },
    };

    render(<ScanListTable scans={[executingScan]} />);

    const radio = screen.getByRole("radio", { name: "Scan not available" });
    expect(radio).toBeDisabled();
  });

  it("enables the radio button for a scheduled scan when graph data is ready from a previous cycle", async () => {
    const user = userEvent.setup();
    const scheduledWithGraph: AttackPathScan = {
      ...createScan(1),
      attributes: {
        ...createScan(1).attributes,
        state: "scheduled",
        progress: 0,
        graph_data_ready: true,
      },
    };

    render(<ScanListTable scans={[scheduledWithGraph]} />);

    const radio = screen.getByRole("radio", { name: "Select scan" });
    expect(radio).toBeEnabled();
    expect(radio).toHaveAttribute("aria-checked", "false");

    await user.click(radio);

    expect(pushMock).toHaveBeenCalledWith(
      "/attack-paths?scanPage=1&scanPageSize=5&scanId=scan-1",
    );
  });

  it("shows a Check icon in the Graph column when graph data is ready", () => {
    render(<ScanListTable scans={[createScan(1)]} />);

    // The Graph column renders a Check icon (lucide-check) when graph_data_ready is true
    const checkIcon = document.querySelector(".lucide-check");
    expect(checkIcon).toBeInTheDocument();
    expect(checkIcon).toHaveClass("text-text-success-primary");
  });

  it("shows a Minus icon in the Graph column when graph data is not ready", () => {
    const noGraphScan: AttackPathScan = {
      ...createScan(1),
      attributes: {
        ...createScan(1).attributes,
        graph_data_ready: false,
      },
    };

    render(<ScanListTable scans={[noGraphScan]} />);

    const minusIcon = document.querySelector(".lucide-minus");
    expect(minusIcon).toBeInTheDocument();
    expect(minusIcon).toHaveClass("text-text-neutral-secondary");
  });
});
