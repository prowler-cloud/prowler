/**
 * Tests for inline-resource-container.tsx
 *
 * Fix 2: SSR crash — createPortal must be guarded by isMounted state
 * Fix 3: Invalid Tailwind class — mt-[-10] → -mt-2.5
 */

import { act, render, screen } from "@testing-library/react";
import type {
  ComponentType,
  HTMLAttributes,
  ReactNode,
  TdHTMLAttributes,
} from "react";
import { describe, expect, it, vi } from "vitest";

// ---------------------------------------------------------------------------
// Mocks
// ---------------------------------------------------------------------------

// Mock next/navigation before component import
vi.mock("next/navigation", () => ({
  useSearchParams: () => new URLSearchParams(),
}));

// Mock heavy deps to avoid cascading import errors
vi.mock("@/actions/findings/findings-by-resource", () => ({
  resolveFindingIds: vi.fn().mockResolvedValue([]),
}));

vi.mock("@/hooks/use-infinite-resources", () => ({
  useInfiniteResources: () => ({
    sentinelRef: vi.fn(),
    refresh: vi.fn(),
    loadMore: vi.fn(),
  }),
}));

vi.mock("@/hooks/use-scroll-hint", () => ({
  useScrollHint: () => ({
    containerRef: vi.fn(),
    sentinelRef: vi.fn(),
    showScrollHint: false,
  }),
}));

vi.mock("@/lib", () => ({
  hasDateOrScanFilter: vi.fn().mockReturnValue(false),
}));

vi.mock("./column-finding-resources", () => ({
  getColumnFindingResources: vi.fn().mockReturnValue([]),
}));

vi.mock("./findings-selection-context", () => ({
  FindingsSelectionContext: {
    Provider: ({ children }: { children: ReactNode; value: unknown }) => (
      <>{children}</>
    ),
  },
}));

vi.mock("./resource-detail-drawer", () => ({
  ResourceDetailDrawer: () => (
    <div data-testid="resource-detail-drawer">Drawer</div>
  ),
  useResourceDetailDrawer: () => ({
    isOpen: false,
    isLoading: false,
    isNavigating: false,
    checkMeta: null,
    currentIndex: 0,
    totalResources: 0,
    currentFinding: null,
    otherFindings: [],
    openDrawer: vi.fn(),
    closeDrawer: vi.fn(),
    navigatePrev: vi.fn(),
    navigateNext: vi.fn(),
    refetchCurrent: vi.fn(),
  }),
}));

vi.mock("@/components/shadcn/skeleton/skeleton", () => ({
  Skeleton: () => <div data-testid="skeleton" />,
}));

vi.mock("@/components/shadcn/spinner/spinner", () => ({
  Spinner: () => <div data-testid="spinner" />,
}));

vi.mock("@/components/ui/table", () => ({
  TableCell: ({
    children,
    ...props
  }: { children?: ReactNode } & TdHTMLAttributes<HTMLTableCellElement>) => (
    <td {...props}>{children}</td>
  ),
  TableRow: ({
    children,
    ...props
  }: { children?: ReactNode } & HTMLAttributes<HTMLTableRowElement>) => (
    <tr {...props}>{children}</tr>
  ),
}));

// framer-motion: render children immediately
vi.mock("framer-motion", () => ({
  AnimatePresence: ({ children }: { children: ReactNode }) => <>{children}</>,
  motion: {
    div: ({
      children,
      ...props
    }: { children?: ReactNode } & HTMLAttributes<HTMLDivElement>) => (
      <div {...props}>{children}</div>
    ),
  },
}));

// lucide-react
vi.mock("lucide-react", () => ({
  ChevronsDown: () => <svg data-testid="chevrons-down" />,
}));

// @tanstack/react-table
vi.mock("@tanstack/react-table", () => ({
  flexRender: (Component: ComponentType | string, ctx: unknown) => {
    if (typeof Component === "function")
      return <Component {...(ctx as object)} />;
    return Component;
  },
  getCoreRowModel: () => vi.fn(),
  useReactTable: () => ({
    getRowModel: () => ({ rows: [] }),
    getVisibleLeafColumns: () => [],
  }),
}));

// ---------------------------------------------------------------------------
// Imports (after mocks)
// ---------------------------------------------------------------------------

import type { FindingGroupRow } from "@/types";

import { InlineResourceContainer } from "./inline-resource-container";

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

const mockGroup: FindingGroupRow = {
  id: "group-1",
  rowType: "group",
  checkId: "s3_bucket_public_access",
  checkTitle: "S3 Bucket Public Access Check",
  resourcesTotal: 3,
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
// Fix 2: Drawer renders without manual createPortal (shadcn Drawer has its own portal)
// ---------------------------------------------------------------------------

describe("InlineResourceContainer — Drawer rendering", () => {
  it("should render without crash", async () => {
    let renderError: Error | null = null;
    try {
      await act(async () => {
        render(
          <table>
            <tbody>
              <InlineResourceContainer
                group={mockGroup}
                resourceSearch=""
                columnCount={10}
                onResourceSelectionChange={vi.fn()}
              />
            </tbody>
          </table>,
        );
      });
    } catch (e) {
      renderError = e as Error;
    }
    expect(renderError).toBeNull();
  });

  it("should render the ResourceDetailDrawer", async () => {
    await act(async () => {
      render(
        <table>
          <tbody>
            <InlineResourceContainer
              group={mockGroup}
              resourceSearch=""
              columnCount={10}
              onResourceSelectionChange={vi.fn()}
            />
          </tbody>
        </table>,
      );
    });
    expect(screen.getByTestId("resource-detail-drawer")).toBeInTheDocument();
  });
});

// ---------------------------------------------------------------------------
// Fix 3: Invalid Tailwind class — -mt-2.5 instead of mt-[-10]
// ---------------------------------------------------------------------------

describe("InlineResourceContainer — Fix 3: Valid Tailwind class", () => {
  it("should use -mt-2.5 (valid Tailwind scale) on the inner resource table", async () => {
    // Given
    let container!: HTMLElement;
    await act(async () => {
      const result = render(
        <table>
          <tbody>
            <InlineResourceContainer
              group={mockGroup}
              resourceSearch=""
              columnCount={10}
              onResourceSelectionChange={vi.fn()}
            />
          </tbody>
        </table>,
      );
      container = result.container;
    });

    // Then — the inner table element must have class "-mt-2.5", NOT "mt-[-10]"
    const innerTable = container.querySelector("table table");
    expect(innerTable).not.toBeNull();
    expect(innerTable!.className).toContain("-mt-2.5");
    expect(innerTable!.className).not.toContain("mt-[-10]");
  });
});
