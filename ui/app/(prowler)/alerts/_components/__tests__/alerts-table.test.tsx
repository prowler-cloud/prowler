import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import type { ReactNode } from "react";
import { beforeEach, describe, expect, it, vi } from "vitest";

import {
  ALERT_AGGREGATE_OPS,
  ALERT_TRIGGER_KINDS,
  type AlertRule,
} from "@/app/(prowler)/alerts/_types";

import { AlertsTable } from "../alerts-table";

const navigationMocks = vi.hoisted(() => ({
  routerPush: vi.fn(),
  currentSearch: "",
}));

vi.mock("next/navigation", () => ({
  usePathname: () => "/alerts",
  useRouter: () => ({ push: navigationMocks.routerPush }),
  useSearchParams: () => new URLSearchParams(navigationMocks.currentSearch),
}));

vi.mock("@/components/ui/table/data-table", () => ({
  DataTable: ({
    columns,
    data,
    metadata,
  }: {
    columns: {
      id?: string;
      size?: number;
      minSize?: number;
      cell?: (context: { row: { original: AlertRule } }) => ReactNode;
    }[];
    data: AlertRule[];
    metadata?: { pagination?: { count?: number } };
  }) => (
    <div>
      {metadata?.pagination?.count !== undefined && (
        <span>{metadata.pagination.count} Total Entries</span>
      )}
      <table>
        <thead>
          <tr>
            {columns.map((column) => (
              <th
                key={column.id}
                data-testid={`column-${column.id}`}
                data-size={column.size}
                data-min-size={column.minSize}
              >
                <button
                  type="button"
                  onClick={() =>
                    navigationMocks.routerPush(`/alerts?sort=${column.id}`, {
                      scroll: false,
                    })
                  }
                >
                  {column.id === "enabled" ? "Status" : column.id}
                </button>
              </th>
            ))}
          </tr>
        </thead>
        <tbody>
          {data.map((alert) => (
            <tr key={alert.id}>
              {columns.map((column) => (
                <td key={`${alert.id}-${column.id}`}>
                  {column.cell?.({ row: { original: alert } })}
                </td>
              ))}
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  ),
}));

vi.mock("@/components/ui/table/data-table-column-header", () => ({
  DataTableColumnHeader: ({ title }: { title: string }) => <span>{title}</span>,
}));

interface AlertRuleOverrides extends Partial<Omit<AlertRule, "attributes">> {
  attributes?: Partial<AlertRule["attributes"]>;
}

const makeRule = (overrides: AlertRuleOverrides = {}): AlertRule => ({
  id: overrides.id ?? "alert-1",
  type: "alert-rules",
  attributes: {
    name: "Critical findings",
    description: "Notify security",
    enabled: true,
    trigger: ALERT_TRIGGER_KINDS.AFTER_SCAN,
    condition: {
      op: ALERT_AGGREGATE_OPS.ANY,
      filter: { severity: ["critical"] },
    },
    schema_version: 1,
    recipient_emails: ["security@example.com"],
    inserted_at: "2026-01-01T10:00:00Z",
    updated_at: "2026-01-02T11:30:00Z",
    ...overrides.attributes,
  },
});

describe("AlertsTable", () => {
  beforeEach(() => {
    navigationMocks.currentSearch = "";
    navigationMocks.routerPush.mockClear();
  });

  it("should render alert rows with dropdown actions and shared pagination", () => {
    // Given / When
    render(
      <AlertsTable
        alerts={[makeRule()]}
        meta={{ pagination: { page: 1, pages: 2, count: 12 }, version: "1" }}
        mutatingId={null}
        onEdit={vi.fn()}
        onToggleEnabled={vi.fn()}
        onDelete={vi.fn()}
      />,
    );

    // Then
    expect(
      screen.getByRole("cell", { name: /critical findings/i }),
    ).toBeVisible();
    expect(
      screen.getByRole("button", { name: /actions for critical findings/i }),
    ).toBeVisible();
    expect(
      screen.queryByRole("button", { name: /edit critical findings/i }),
    ).not.toBeInTheDocument();
    expect(screen.getByText(/12 total entries/i)).toBeVisible();
    expect(screen.getByTestId("column-actions")).toHaveAttribute(
      "data-size",
      "72",
    );
    expect(screen.getByTestId("column-name")).toHaveAttribute(
      "data-size",
      "320",
    );
    expect(screen.getByTestId("column-inserted_at")).toHaveAttribute(
      "data-size",
      "170",
    );
    expect(screen.getByTestId("column-updated_at")).toHaveAttribute(
      "data-size",
      "170",
    );
    expect(screen.getByText("Jan 01, 2026")).toBeVisible();
    expect(screen.getByText("Jan 02, 2026")).toBeVisible();
    expect(
      screen.queryByRole("button", { name: /run preview|test/i }),
    ).not.toBeInTheDocument();
    expect(
      screen.queryByRole("link", { name: /critical findings/i }),
    ).not.toBeInTheDocument();
  });

  it("should truncate long descriptions in the name column", () => {
    // Given
    const description =
      "This alert description is intentionally long enough to overflow the alerts table if it is not constrained by the cell renderer.";

    // When
    render(
      <AlertsTable
        alerts={[makeRule({ attributes: { description } })]}
        mutatingId={null}
        onEdit={vi.fn()}
        onToggleEnabled={vi.fn()}
        onDelete={vi.fn()}
      />,
    );

    // Then
    expect(screen.getByText(description)).toHaveClass("truncate");
    expect(screen.getByText(description).parentElement).toHaveClass(
      "max-w-[320px]",
    );
    expect(screen.getByText(description)).toHaveAttribute("title", description);
  });

  it("should call row action callbacks for edit, toggle, and delete", async () => {
    // Given
    const user = userEvent.setup();
    const alert = makeRule({ id: "alert-enabled" });
    const onEdit = vi.fn();
    const onToggleEnabled = vi.fn();
    const onDelete = vi.fn();
    render(
      <AlertsTable
        alerts={[alert]}
        mutatingId={null}
        onEdit={onEdit}
        onToggleEnabled={onToggleEnabled}
        onDelete={onDelete}
      />,
    );

    // When
    await user.click(
      screen.getByRole("button", { name: /actions for critical findings/i }),
    );
    await user.click(screen.getByRole("menuitem", { name: /edit/i }));
    await user.click(
      screen.getByRole("button", { name: /actions for critical findings/i }),
    );
    await user.click(screen.getByRole("menuitem", { name: /disable/i }));
    await user.click(
      screen.getByRole("button", { name: /actions for critical findings/i }),
    );
    await user.click(screen.getByRole("menuitem", { name: /delete/i }));

    // Then
    expect(onEdit).toHaveBeenCalledWith(alert);
    expect(onToggleEnabled).toHaveBeenCalledWith(alert);
    expect(onDelete).toHaveBeenCalledWith(alert);
  });

  it("should edit the alert directly when clicking the alert name", async () => {
    // Given
    const user = userEvent.setup();
    const alert = makeRule();
    const onEdit = vi.fn();
    render(
      <AlertsTable
        alerts={[alert]}
        mutatingId={null}
        onEdit={onEdit}
        onToggleEnabled={vi.fn()}
        onDelete={vi.fn()}
      />,
    );

    // When
    await user.click(screen.getByRole("button", { name: "Critical findings" }));

    // Then
    expect(onEdit).toHaveBeenCalledWith(alert);
    expect(screen.queryByRole("menuitem", { name: /edit/i })).toBeNull();
    expect(screen.queryByRole("menuitem", { name: /disable/i })).toBeNull();
    expect(screen.queryByRole("menuitem", { name: /delete/i })).toBeNull();
  });
});
