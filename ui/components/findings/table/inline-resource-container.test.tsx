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
import { beforeEach, describe, expect, it, vi } from "vitest";

// ---------------------------------------------------------------------------
// Mocks
// ---------------------------------------------------------------------------

// Hoist createPortal spy so it is available when the vi.mock factory runs.
// vi.hoisted() runs before all imports, making the spy available in the factory.
const { createPortalSpy } = vi.hoisted(() => ({
  createPortalSpy: vi.fn(),
}));

vi.mock("react-dom", async (importOriginal) => {
  const original = await importOriginal<typeof import("react-dom")>();
  // Delegate to the real createPortal so other tests keep working,
  // but allow spy assertions on call count and timing.
  createPortalSpy.mockImplementation(original.createPortal);
  return {
    ...original,
    createPortal: createPortalSpy,
  };
});

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
// Fix 2: SSR crash — portal only mounted after client-side mount
// ---------------------------------------------------------------------------

describe("InlineResourceContainer — Fix 2: SSR portal guard", () => {
  beforeEach(() => {
    createPortalSpy.mockClear();
  });

  it("should render without crash when document.body exists (JSDOM)", async () => {
    // Given — JSDOM has document.body; this verifies the happy path
    let renderError: Error | null = null;

    // When
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

    // Then — component must not throw
    expect(renderError).toBeNull();
  });

  it("should render the portal content (ResourceDetailDrawer) after mount", async () => {
    // Given
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

    // Then — drawer appears in the document via portal after mount
    expect(screen.getByTestId("resource-detail-drawer")).toBeInTheDocument();
  });

  it("should NOT call createPortal synchronously on initial render — only after useEffect fires (isMounted guard)", () => {
    // Given — createPortalSpy is reset by beforeEach, so call count starts at 0.
    // Before the fix: createPortal runs on the initial synchronous render → crash in SSR.
    // After the fix: createPortal is guarded by isMounted (set via useEffect).
    // useEffect fires AFTER commit, so createPortal must NOT be called
    // during the synchronous render phase.

    // When — render inside synchronous act() and capture spy count INSIDE the callback.
    // In React 19, act() DOES flush effects — but the callback runs BEFORE effects drain.
    // So: the callback body executes first (synchronous render only), THEN act() flushes
    // pending effects after the callback returns.
    // Capturing spy state inside the callback captures the pre-effect state.
    let portalCallsAfterSyncRender = 0;
    act(() => {
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
      // Capture call count here — inside the callback = after synchronous render,
      // but BEFORE act() drains pending effects (effects flush after this returns).
      portalCallsAfterSyncRender = createPortalSpy.mock.calls.length;
    });
    // After the callback returns, act() flushes pending effects (isMounted = true → re-render)

    // Then — createPortal must NOT have been called during the synchronous render phase
    // (isMounted starts as false, createPortal is inside {isMounted && createPortal(...)})
    expect(portalCallsAfterSyncRender).toBe(0);

    // After act() completes, effects have flushed → isMounted = true → re-render → createPortal called
    expect(createPortalSpy).toHaveBeenCalled();
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
