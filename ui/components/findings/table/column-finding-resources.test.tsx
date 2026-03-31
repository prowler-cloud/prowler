/**
 * Tests for column-finding-resources.tsx
 *
 * Fix 4: Muted resource rows should show a visible "Muted" badge/indicator
 *        in the status cell (not just the tiny 2px NotificationIndicator dot).
 */

import { render, screen } from "@testing-library/react";
import type { InputHTMLAttributes, ReactNode } from "react";
import { describe, expect, it, vi } from "vitest";

// ---------------------------------------------------------------------------
// Mocks
// ---------------------------------------------------------------------------

vi.mock("next/navigation", () => ({
  useRouter: () => ({ refresh: vi.fn() }),
  useSearchParams: () => new URLSearchParams(),
}));

vi.mock("next/link", () => ({
  default: ({ children, href }: { children: ReactNode; href: string }) => (
    <a href={href}>{children}</a>
  ),
}));

vi.mock("@/components/findings/mute-findings-modal", () => ({
  MuteFindingsModal: () => null,
}));

vi.mock("@/components/shadcn", () => ({
  Checkbox: ({
    "aria-label": ariaLabel,
    ...props
  }: InputHTMLAttributes<HTMLInputElement> & {
    "aria-label"?: string;
    size?: string;
  }) => <input type="checkbox" aria-label={ariaLabel} {...props} />,
}));

vi.mock("@/components/shadcn/dropdown", () => ({
  ActionDropdown: ({ children }: { children: ReactNode }) => (
    <div>{children}</div>
  ),
  ActionDropdownItem: () => null,
}));

vi.mock("@/components/shadcn/info-field/info-field", () => ({
  InfoField: ({
    children,
    label,
  }: {
    children: ReactNode;
    label: string;
    variant?: string;
  }) => (
    <div>
      <span>{label}</span>
      {children}
    </div>
  ),
}));

vi.mock("@/components/shadcn/spinner/spinner", () => ({
  Spinner: () => <div data-testid="spinner" />,
}));

vi.mock("@/components/shadcn/tooltip", () => ({
  Tooltip: ({ children }: { children: ReactNode }) => <>{children}</>,
  TooltipContent: ({ children }: { children: ReactNode }) => <>{children}</>,
  TooltipTrigger: ({ children }: { children: ReactNode }) => <>{children}</>,
}));

vi.mock("@/components/ui/entities", () => ({
  DateWithTime: ({ dateTime }: { dateTime: string }) => <span>{dateTime}</span>,
}));

vi.mock("@/components/ui/entities/entity-info", () => ({
  EntityInfo: () => null,
}));

vi.mock("@/components/ui/table", () => ({
  DataTableColumnHeader: ({ title }: { column: unknown; title: string }) => (
    <span>{title}</span>
  ),
  SeverityBadge: ({ severity }: { severity: string }) => (
    <span data-testid="severity-badge">{severity}</span>
  ),
}));

vi.mock("@/components/ui/table/status-finding-badge", () => ({
  StatusFindingBadge: ({ status }: { status: string }) => (
    <span data-testid="status-badge">{status}</span>
  ),
}));

vi.mock("@/components/ui/table/data-table-column-header", () => ({
  DataTableColumnHeader: ({ title }: { column: unknown; title: string }) => (
    <span>{title}</span>
  ),
}));

vi.mock("@/lib/date-utils", () => ({
  getFailingForLabel: vi.fn(() => "2 days"),
}));

vi.mock("@/lib", () => ({
  cn: (...args: (string | undefined | false | null)[]) =>
    args.filter(Boolean).join(" "),
}));

vi.mock("./findings-selection-context", () => ({
  FindingsSelectionContext: {
    Provider: ({ children }: { children: ReactNode; value: unknown }) => (
      <>{children}</>
    ),
  },
  default: {
    Provider: ({ children }: { children: ReactNode; value: unknown }) => (
      <>{children}</>
    ),
  },
}));

vi.mock("./notification-indicator", () => ({
  NotificationIndicator: ({
    isMuted,
  }: {
    isMuted?: boolean;
    mutedReason?: string;
  }) => (
    <div
      data-testid="notification-indicator"
      data-is-muted={isMuted ? "true" : "false"}
    />
  ),
}));

vi.mock("lucide-react", () => ({
  Container: () => <svg data-testid="container-icon" />,
  CornerDownRight: () => <svg data-testid="corner-icon" />,
  VolumeOff: () => <svg data-testid="volume-off-icon" />,
  VolumeX: () => <svg data-testid="volume-x-icon" />,
}));

vi.mock("@tanstack/react-table", () => ({}));

// ---------------------------------------------------------------------------
// Import after mocks
// ---------------------------------------------------------------------------

import type { FindingResourceRow } from "@/types";

import { getColumnFindingResources } from "./column-finding-resources";

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function makeResource(
  overrides?: Partial<FindingResourceRow>,
): FindingResourceRow {
  return {
    id: "resource-1",
    rowType: "resource" as const,
    findingId: "finding-1",
    checkId: "s3_check",
    providerType: "aws",
    providerAlias: "prod",
    providerUid: "123456789",
    resourceName: "my-bucket",
    resourceGroup: "default",
    resourceUid: "arn:aws:s3:::my-bucket",
    service: "s3",
    region: "us-east-1",
    severity: "high",
    status: "FAIL",
    isMuted: false,
    mutedReason: undefined,
    firstSeenAt: "2024-01-01T00:00:00Z",
    lastSeenAt: "2024-01-02T00:00:00Z",
    ...overrides,
  };
}

function renderStatusCell(resource: FindingResourceRow) {
  const columns = getColumnFindingResources({
    rowSelection: {},
    selectableRowCount: 1,
  });

  const statusColumn = columns.find(
    (col) => "id" in col && col.id === "status",
  );
  if (!statusColumn?.cell) throw new Error("status column not found");

  const CellComponent = statusColumn.cell as (props: {
    row: { original: FindingResourceRow };
  }) => ReactNode;

  const { container } = render(
    <div>{CellComponent({ row: { original: resource } })}</div>,
  );
  return container;
}

// ---------------------------------------------------------------------------
// Fix 4: Muted resource rows must show a visible "Muted" indicator
// ---------------------------------------------------------------------------

describe("column-finding-resources — Fix 4: Muted indicator in resource rows", () => {
  it("should show a 'Muted' text indicator when isMuted is true", () => {
    // Given
    const mutedResource = makeResource({
      isMuted: true,
      status: "MUTED",
      mutedReason: "Test mute rule",
    });

    // When
    renderStatusCell(mutedResource);

    // Then — a visible "Muted" label should appear
    expect(screen.getByText(/muted/i)).toBeInTheDocument();
  });

  it("should NOT show a 'Muted' indicator when isMuted is false", () => {
    // Given
    const activeResource = makeResource({ isMuted: false, status: "FAIL" });

    // When
    renderStatusCell(activeResource);

    // Then — no "Muted" text should appear in the status cell
    const mutedText = screen.queryByText(/^muted$/i);
    expect(mutedText).toBeNull();
  });

  it("should show 'FAIL' status badge for non-muted resources", () => {
    // Given
    const activeResource = makeResource({ isMuted: false, status: "FAIL" });

    // When
    renderStatusCell(activeResource);

    // Then
    expect(screen.getByTestId("status-badge")).toBeInTheDocument();
    expect(screen.getByTestId("status-badge")).toHaveTextContent("FAIL");
  });

  it("should show FAIL status badge alongside Muted indicator for muted resources", () => {
    // Given — muted resources still show FAIL status (MUTED → FAIL conversion)
    const mutedResource = makeResource({ isMuted: true, status: "MUTED" });

    // When
    renderStatusCell(mutedResource);

    // Then — both FAIL badge and Muted indicator should appear
    expect(screen.getByTestId("status-badge")).toBeInTheDocument();
    expect(screen.getByText(/muted/i)).toBeInTheDocument();
  });
});
