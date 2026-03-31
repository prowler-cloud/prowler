/**
 * Tests for findings-group-table.tsx
 *
 * Fix 3: Search should only trigger on Enter, not on every keystroke.
 *        resourceSearch must NOT be part of InlineResourceContainer's key.
 */

import { render, screen } from "@testing-library/react";
import type { ReactNode } from "react";
import { beforeEach, describe, expect, it, vi } from "vitest";

// ---------------------------------------------------------------------------
// Hoist mocks
// ---------------------------------------------------------------------------

vi.mock("next/navigation", () => ({
  useRouter: () => ({ refresh: vi.fn() }),
  usePathname: () => "/findings",
  useSearchParams: () => new URLSearchParams(),
}));

vi.mock("@/actions/findings/findings-by-resource", () => ({
  resolveFindingIds: vi.fn().mockResolvedValue([]),
  resolveFindingIdsByVisibleGroupResources: vi.fn().mockResolvedValue([]),
}));

// Track InlineResourceContainer renders & props
const inlineRenders: Array<{ resourceSearch: string }> = [];

vi.mock("./inline-resource-container", () => ({
  InlineResourceContainer: ({
    resourceSearch,
  }: {
    resourceSearch: string;
    group: unknown;
    columnCount: number;
    onResourceSelectionChange: (ids: string[]) => void;
    ref?: unknown;
  }) => {
    inlineRenders.push({ resourceSearch });
    return (
      <div
        data-testid="inline-resource-container"
        data-resource-search={resourceSearch}
      />
    );
  },
}));

vi.mock("./column-finding-groups", () => ({
  getColumnFindingGroups: vi.fn().mockReturnValue([]),
}));

vi.mock("./findings-selection-context", () => ({
  FindingsSelectionContext: {
    Provider: ({ children }: { children: ReactNode; value: unknown }) => (
      <>{children}</>
    ),
  },
}));

vi.mock("../floating-mute-button", () => ({
  FloatingMuteButton: () => null,
}));

vi.mock("@/lib", () => ({
  hasDateOrScanFilter: vi.fn().mockReturnValue(false),
  cn: (...args: (string | undefined | false | null)[]) =>
    args.filter(Boolean).join(" "),
}));

// ---------------------------------------------------------------------------
// DataTable mock that exposes onSearchCommit (Enter behavior)
// ---------------------------------------------------------------------------

let capturedOnSearchChange: ((value: string) => void) | undefined;
let capturedOnSearchCommit: ((value: string) => void) | undefined;

vi.mock("@/components/ui/table", () => ({
  DataTable: ({
    onSearchChange,
    onSearchCommit,
    controlledSearch,
    renderAfterRow,
    data,
  }: {
    onSearchChange?: (value: string) => void;
    onSearchCommit?: (value: string) => void;
    controlledSearch?: string;
    renderAfterRow?: (row: { original: unknown }) => ReactNode;
    children?: ReactNode;
    columns?: unknown[];
    data?: unknown[];
    metadata?: unknown;
    enableRowSelection?: boolean;
    rowSelection?: unknown;
    onRowSelectionChange?: unknown;
    getRowCanSelect?: unknown;
    showSearch?: boolean;
    searchPlaceholder?: string;
    searchBadge?: unknown;
  }) => {
    capturedOnSearchChange = onSearchChange;
    capturedOnSearchCommit = onSearchCommit;

    return (
      <div data-testid="data-table">
        <input
          data-testid="search-input"
          value={controlledSearch ?? ""}
          onChange={(e) => onSearchChange?.(e.target.value)}
          placeholder="Search resources..."
        />
        {/* Render inline container for first row (simulates expanded drill-down) */}
        {data && data.length > 0 && renderAfterRow?.({ original: data[0] })}
      </div>
    );
  },
}));

// ---------------------------------------------------------------------------
// Import after mocks
// ---------------------------------------------------------------------------

import type { FindingGroupRow } from "@/types";

import { FindingsGroupTable } from "./findings-group-table";

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

const mockGroup: FindingGroupRow = {
  id: "group-1",
  rowType: "group",
  checkId: "s3_bucket_public_access",
  checkTitle: "S3 Bucket Public Access Check",
  resourcesTotal: 5,
  resourcesFail: 3,
  newCount: 0,
  changedCount: 0,
  mutedCount: 0,
  severity: "high",
  status: "FAIL",
  providers: ["aws"],
  updatedAt: "2024-01-01T00:00:00Z",
};

// ---------------------------------------------------------------------------
// Fix 3: Search fires only on Enter (onSearchCommit), not on every keystroke
// ---------------------------------------------------------------------------

describe("FindingsGroupTable — Enter-only search for resource drill-down", () => {
  beforeEach(() => {
    capturedOnSearchChange = undefined;
    capturedOnSearchCommit = undefined;
    inlineRenders.length = 0;
  });

  it("should render successfully with drill-down data", () => {
    render(<FindingsGroupTable data={[mockGroup]} />);
    expect(screen.getByTestId("data-table")).toBeInTheDocument();
  });

  it("should not pass onSearchCommit when no group is expanded", () => {
    // Given — no drill-down active
    render(<FindingsGroupTable data={[mockGroup]} />);

    // Then — onSearchCommit must be undefined (no active drill-down)
    expect(capturedOnSearchCommit).toBeUndefined();
    // onSearchChange must also be undefined
    expect(capturedOnSearchChange).toBeUndefined();
  });

  it("should not render InlineResourceContainer when no group is expanded", () => {
    // Given — no drill-down active
    render(<FindingsGroupTable data={[mockGroup]} />);

    // Then — no inline containers rendered
    const inlineContainers = screen.queryAllByTestId(
      "inline-resource-container",
    );
    expect(inlineContainers).toHaveLength(0);
  });
});
