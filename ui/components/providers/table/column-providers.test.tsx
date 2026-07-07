import { render, screen } from "@testing-library/react";
import type { ReactNode } from "react";
import { describe, expect, it, vi } from "vitest";

import {
  PROVIDERS_ROW_TYPE,
  type ProvidersProviderRow,
  type ProvidersTableRow,
} from "@/types/providers-table";

import { getColumnProviders } from "./column-providers";

vi.mock("@/components/shadcn", () => ({
  Badge: ({ children }: { children: ReactNode }) => <span>{children}</span>,
}));

vi.mock("@/components/shadcn/checkbox/checkbox", () => ({
  Checkbox: () => null,
}));

vi.mock("@/components/shadcn/code-snippet/code-snippet", () => ({
  CodeSnippet: ({ value }: { value: string }) => <code>{value}</code>,
}));

vi.mock("@/components/shadcn/entities", () => ({
  DateWithTime: ({ dateTime }: { dateTime: string | null }) => (
    <time>{dateTime}</time>
  ),
  EntityInfo: ({
    entityAlias,
    entityId,
  }: {
    entityAlias?: string;
    entityId?: string;
  }) => <span>{entityAlias ?? entityId}</span>,
}));

vi.mock("@/components/shadcn/table", () => ({
  DataTableColumnHeader: ({ title }: { title: string }) => <span>{title}</span>,
}));

vi.mock("@/components/shadcn/table/data-table-expand-all-toggle", () => ({
  DataTableExpandAllToggle: () => null,
}));

vi.mock("@/components/shadcn/table/data-table-expandable-cell", () => ({
  DataTableExpandableCell: ({ children }: { children: ReactNode }) => (
    <div>{children}</div>
  ),
}));

vi.mock("../link-to-scans", () => ({
  LinkToScans: () => null,
}));

vi.mock("./data-table-row-actions", () => ({
  DataTableRowActions: () => null,
}));

const providerRow: ProvidersProviderRow = {
  id: "provider-1",
  rowType: PROVIDERS_ROW_TYPE.PROVIDER,
  type: "providers",
  attributes: {
    provider: "aws",
    uid: "123456789012",
    alias: "Production",
    status: "completed",
    resources: 0,
    connection: {
      connected: true,
      last_checked_at: "2026-01-01T00:00:00Z",
    },
    scanner_args: {
      only_logs: false,
      excluded_checks: [],
      aws_retries_max_attempts: 3,
    },
    inserted_at: "2026-01-01T00:00:00Z",
    updated_at: "2026-01-01T00:00:00Z",
    created_by: {
      object: "user",
      id: "user-1",
    },
  },
  relationships: {
    secret: { data: { id: "secret-1", type: "secrets" } },
    provider_groups: { meta: { count: 0 }, data: [] },
  },
  groupNames: [],
  hasSchedule: false,
};

function renderLastScanCell(row: ProvidersTableRow) {
  const lastScanColumn = getColumnProviders(
    {},
    [],
    [],
    [],
    vi.fn(),
    vi.fn(),
    vi.fn(),
  ).find((column) => column.id === "lastScan");

  const cell = lastScanColumn?.cell;
  if (typeof cell !== "function") {
    throw new Error("Last Scan column cell renderer not found");
  }

  const element = cell({
    row: { original: row },
  } as unknown as Parameters<typeof cell>[0]);

  render(<>{element as ReactNode}</>);
}

describe("getColumnProviders", () => {
  it("falls back to connection last_checked_at when lastScanAt is undefined", () => {
    renderLastScanCell({ ...providerRow, lastScanAt: undefined });

    expect(screen.getByText("2026-01-01T00:00:00Z")).toBeVisible();
    expect(screen.queryByText("Never")).not.toBeInTheDocument();
  });

  it("treats a null lastScanAt as authoritative", () => {
    renderLastScanCell({ ...providerRow, lastScanAt: null });

    expect(screen.getByText("Never")).toBeVisible();
    expect(screen.queryByText("2026-01-01T00:00:00Z")).not.toBeInTheDocument();
  });
});
