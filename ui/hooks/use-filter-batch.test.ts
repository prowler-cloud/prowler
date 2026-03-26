import { act, renderHook } from "@testing-library/react";
import { beforeEach, describe, expect, it, vi } from "vitest";

// --- Mock next/navigation ---
const mockPush = vi.fn();
let mockSearchParamsValue = new URLSearchParams();

vi.mock("next/navigation", () => ({
  useRouter: () => ({ push: mockPush }),
  usePathname: () => "/findings",
  useSearchParams: () => mockSearchParamsValue,
}));

import { useFilterBatch } from "./use-filter-batch";

/**
 * Helper to re-assign the mocked searchParams and re-import the hook.
 * Because useSearchParams() is called inside the hook on every render,
 * we just update the module-level variable and force a re-render.
 */
function setSearchParams(params: Record<string, string>) {
  mockSearchParamsValue = new URLSearchParams(params);
}

describe("useFilterBatch", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    mockSearchParamsValue = new URLSearchParams();
  });

  // ── Initial state ──────────────────────────────────────────────────────────

  describe("initial state", () => {
    it("should have empty pending filters when there are no URL params", () => {
      // Given
      setSearchParams({});

      // When
      const { result } = renderHook(() => useFilterBatch());

      // Then
      expect(result.current.pendingFilters).toEqual({});
      expect(result.current.hasChanges).toBe(false);
      expect(result.current.changeCount).toBe(0);
    });

    it("should initialize pending filters from URL search params on mount", () => {
      // Given
      setSearchParams({
        "filter[severity__in]": "critical,high",
        "filter[status__in]": "FAIL",
      });

      // When
      const { result } = renderHook(() => useFilterBatch());

      // Then
      expect(result.current.pendingFilters).toEqual({
        "filter[severity__in]": ["critical", "high"],
        "filter[status__in]": ["FAIL"],
      });
      expect(result.current.hasChanges).toBe(false);
    });
  });

  // ── Excluded keys ──────────────────────────────────────────────────────────

  describe("excluded keys", () => {
    it("should exclude filter[search] from batch operations", () => {
      // Given — search is excluded from batch; muted now participates in batch
      setSearchParams({
        "filter[search]": "some-search-term",
        "filter[muted]": "false",
        "filter[severity__in]": "critical",
      });

      // When
      const { result } = renderHook(() => useFilterBatch());

      // Then — severity and muted are in pendingFilters; search is excluded
      expect(result.current.pendingFilters).toEqual({
        "filter[muted]": ["false"],
        "filter[severity__in]": ["critical"],
      });
      expect(result.current.pendingFilters["filter[search]"]).toBeUndefined();
      // muted is now part of batch (not excluded)
      expect(result.current.pendingFilters["filter[muted]"]).toEqual(["false"]);
    });
  });

  // ── setPending ─────────────────────────────────────────────────────────────

  describe("setPending", () => {
    it("should update pending state for a given key", () => {
      // Given
      setSearchParams({});
      const { result } = renderHook(() => useFilterBatch());

      // When
      act(() => {
        result.current.setPending("filter[severity__in]", ["critical", "high"]);
      });

      // Then
      expect(result.current.pendingFilters["filter[severity__in]"]).toEqual([
        "critical",
        "high",
      ]);
    });

    it("should auto-prefix key with filter[] when not already prefixed", () => {
      // Given
      setSearchParams({});
      const { result } = renderHook(() => useFilterBatch());

      // When
      act(() => {
        result.current.setPending("severity__in", ["critical"]);
      });

      // Then — key is stored with filter[] prefix
      expect(result.current.pendingFilters["filter[severity__in]"]).toEqual([
        "critical",
      ]);
    });

    it("should keep the key but with empty array when values is empty", () => {
      // Given
      setSearchParams({});
      const { result } = renderHook(() => useFilterBatch());

      // Pre-condition: set a value first
      act(() => {
        result.current.setPending("filter[severity__in]", ["critical"]);
      });

      // When — clear the filter by passing empty array
      act(() => {
        result.current.setPending("filter[severity__in]", []);
      });

      // Then
      expect(result.current.pendingFilters["filter[severity__in]"]).toEqual([]);
    });
  });

  // ── getFilterValue ─────────────────────────────────────────────────────────

  describe("getFilterValue", () => {
    it("should return pending values for a key that has been set", () => {
      // Given
      setSearchParams({});
      const { result } = renderHook(() => useFilterBatch());

      act(() => {
        result.current.setPending("filter[severity__in]", ["critical", "high"]);
      });

      // When
      const values = result.current.getFilterValue("filter[severity__in]");

      // Then
      expect(values).toEqual(["critical", "high"]);
    });

    it("should return an empty array for a key that has not been set", () => {
      // Given
      setSearchParams({});
      const { result } = renderHook(() => useFilterBatch());

      // When
      const values = result.current.getFilterValue("filter[unknown_key]");

      // Then
      expect(values).toEqual([]);
    });

    it("should auto-prefix key when calling getFilterValue without filter[]", () => {
      // Given
      setSearchParams({});
      const { result } = renderHook(() => useFilterBatch());

      act(() => {
        result.current.setPending("filter[severity__in]", ["critical"]);
      });

      // When — key without prefix
      const values = result.current.getFilterValue("severity__in");

      // Then
      expect(values).toEqual(["critical"]);
    });
  });

  // ── hasChanges & changeCount ───────────────────────────────────────────────

  describe("hasChanges", () => {
    it("should be false when pending matches the URL state", () => {
      // Given
      setSearchParams({ "filter[severity__in]": "critical" });
      const { result } = renderHook(() => useFilterBatch());

      // Then — initial state = URL state, so no changes
      expect(result.current.hasChanges).toBe(false);
    });

    it("should be true when pending differs from the URL state", () => {
      // Given
      setSearchParams({ "filter[severity__in]": "critical" });
      const { result } = renderHook(() => useFilterBatch());

      // When — change pending
      act(() => {
        result.current.setPending("filter[severity__in]", ["critical", "high"]);
      });

      // Then
      expect(result.current.hasChanges).toBe(true);
    });
  });

  describe("changeCount", () => {
    it("should be 0 when pending matches URL", () => {
      // Given
      setSearchParams({ "filter[severity__in]": "critical" });
      const { result } = renderHook(() => useFilterBatch());

      // Then
      expect(result.current.changeCount).toBe(0);
    });

    it("should count the number of changed filter keys", () => {
      // Given
      setSearchParams({});
      const { result } = renderHook(() => useFilterBatch());

      // When — add two different pending filters
      act(() => {
        result.current.setPending("filter[severity__in]", ["critical"]);
        result.current.setPending("filter[status__in]", ["FAIL"]);
      });

      // Then — 2 keys differ from URL (which has neither)
      expect(result.current.changeCount).toBe(2);
    });

    it("should decrease changeCount when a pending filter is reset to match URL", () => {
      // Given — URL has severity=critical, pending adds status=FAIL
      setSearchParams({ "filter[severity__in]": "critical" });
      const { result } = renderHook(() => useFilterBatch());

      act(() => {
        result.current.setPending("filter[status__in]", ["FAIL"]);
      });

      expect(result.current.changeCount).toBe(1);

      // When — reset status back to empty (matching URL which has no status)
      act(() => {
        result.current.setPending("filter[status__in]", []);
      });

      // Then
      expect(result.current.changeCount).toBe(0);
    });
  });

  // ── applyAll ───────────────────────────────────────────────────────────────

  describe("applyAll", () => {
    it("should call router.push with all pending filters serialized as URL params", () => {
      // Given
      setSearchParams({});
      const { result } = renderHook(() => useFilterBatch());

      act(() => {
        result.current.setPending("filter[severity__in]", ["critical", "high"]);
      });

      // When
      act(() => {
        result.current.applyAll();
      });

      // Then
      expect(mockPush).toHaveBeenCalledTimes(1);
      const calledUrl: string = mockPush.mock.calls[0][0];
      expect(calledUrl).toContain("filter%5Bseverity__in%5D=critical%2Chigh");
    });

    it("should reset page number when a page param exists in the URL", () => {
      // Given — simulate a URL that already has page=3
      mockSearchParamsValue = new URLSearchParams({
        "filter[severity__in]": "critical",
        page: "3",
      });

      const { result } = renderHook(() => useFilterBatch());

      act(() => {
        result.current.setPending("filter[status__in]", ["FAIL"]);
      });

      // When
      act(() => {
        result.current.applyAll();
      });

      // Then — page should be reset to 1
      const calledUrl: string = mockPush.mock.calls[0][0];
      expect(calledUrl).toContain("page=1");
    });

    it("should preserve excluded params (filter[search], filter[muted]) in the URL", () => {
      // Given
      mockSearchParamsValue = new URLSearchParams({
        "filter[search]": "my-search",
        "filter[muted]": "false",
      });

      const { result } = renderHook(() => useFilterBatch());

      act(() => {
        result.current.setPending("filter[severity__in]", ["critical"]);
      });

      // When
      act(() => {
        result.current.applyAll();
      });

      // Then — search and muted should still be present
      const calledUrl: string = mockPush.mock.calls[0][0];
      expect(calledUrl).toContain("filter%5Bsearch%5D=my-search");
      expect(calledUrl).toContain("filter%5Bmuted%5D=false");
    });
  });

  // ── discardAll ─────────────────────────────────────────────────────────────

  describe("discardAll", () => {
    it("should reset pending to match the current URL state", () => {
      // Given — URL has severity=critical
      setSearchParams({ "filter[severity__in]": "critical" });
      const { result } = renderHook(() => useFilterBatch());

      // Add a pending change
      act(() => {
        result.current.setPending("filter[severity__in]", ["critical", "high"]);
        result.current.setPending("filter[status__in]", ["FAIL"]);
      });

      expect(result.current.hasChanges).toBe(true);

      // When
      act(() => {
        result.current.discardAll();
      });

      // Then — pending should match URL again
      expect(result.current.pendingFilters).toEqual({
        "filter[severity__in]": ["critical"],
      });
      expect(result.current.hasChanges).toBe(false);
    });
  });

  // ── URL sync (back/forward) ────────────────────────────────────────────────

  describe("URL sync", () => {
    it("should re-sync pending state when searchParams change (e.g., browser back/forward)", () => {
      // Given — initial empty URL
      setSearchParams({});
      const { result, rerender } = renderHook(() => useFilterBatch());

      // Add a pending change
      act(() => {
        result.current.setPending("filter[severity__in]", ["critical"]);
      });

      expect(result.current.pendingFilters["filter[severity__in]"]).toEqual([
        "critical",
      ]);

      // When — simulate browser back by changing searchParams externally
      act(() => {
        mockSearchParamsValue = new URLSearchParams({
          "filter[severity__in]": "high",
        });
      });
      rerender();

      // Then — pending should re-sync from new URL
      expect(result.current.pendingFilters["filter[severity__in]"]).toEqual([
        "high",
      ]);
    });
  });

  // ── removePending ──────────────────────────────────────────────────────────

  describe("removePending", () => {
    it("should remove a single filter key from pending state", () => {
      // Given
      setSearchParams({});
      const { result } = renderHook(() => useFilterBatch());

      act(() => {
        result.current.setPending("filter[severity__in]", ["critical"]);
        result.current.setPending("filter[status__in]", ["FAIL"]);
      });

      // When
      act(() => {
        result.current.removePending("filter[severity__in]");
      });

      // Then
      expect(
        result.current.pendingFilters["filter[severity__in]"],
      ).toBeUndefined();
      expect(result.current.pendingFilters["filter[status__in]"]).toEqual([
        "FAIL",
      ]);
    });
  });

  // ── clearAndApply ──────────────────────────────────────────────────────────

  describe("clearAndApply", () => {
    it("should clear all batch-managed filters and push URL immediately", () => {
      // Given
      setSearchParams({
        "filter[severity__in]": "critical",
        "filter[status__in]": "FAIL",
      });
      const { result } = renderHook(() => useFilterBatch());

      // Pre-condition — pending is loaded from URL
      expect(result.current.pendingFilters["filter[severity__in]"]).toEqual([
        "critical",
      ]);
      expect(result.current.pendingFilters["filter[status__in]"]).toEqual([
        "FAIL",
      ]);

      // When
      act(() => {
        result.current.clearAndApply();
      });

      // Then — pending is empty
      expect(result.current.pendingFilters).toEqual({});

      // And router.push was called
      expect(mockPush).toHaveBeenCalledTimes(1);
      const calledUrl: string = mockPush.mock.calls[0][0];

      // The pushed URL must NOT contain severity or status
      expect(calledUrl).not.toContain("severity");
      expect(calledUrl).not.toContain("status");
    });

    it("should apply defaultParams when clearing", () => {
      // Given
      setSearchParams({ "filter[severity__in]": "critical" });
      const { result } = renderHook(() =>
        useFilterBatch({ defaultParams: { "filter[muted]": "false" } }),
      );

      // When
      act(() => {
        result.current.clearAndApply();
      });

      // Then — pushed URL contains the defaultParam
      expect(mockPush).toHaveBeenCalledTimes(1);
      const calledUrl: string = mockPush.mock.calls[0][0];
      expect(calledUrl).toContain("filter%5Bmuted%5D=false");
    });

    it("should preserve filter[search] (excluded from batch)", () => {
      // Given — URL has both a search param (excluded) and a batch filter
      mockSearchParamsValue = new URLSearchParams({
        "filter[search]": "test",
        "filter[severity__in]": "critical",
      });
      const { result } = renderHook(() => useFilterBatch());

      // When
      act(() => {
        result.current.clearAndApply();
      });

      // Then — search param is preserved; severity is gone
      expect(mockPush).toHaveBeenCalledTimes(1);
      const calledUrl: string = mockPush.mock.calls[0][0];
      expect(calledUrl).toContain("filter%5Bsearch%5D=test");
      expect(calledUrl).not.toContain("severity");
    });

    it("should reset pagination to page 1", () => {
      // Given — URL already has a page param
      mockSearchParamsValue = new URLSearchParams({
        "filter[severity__in]": "critical",
        page: "3",
      });
      const { result } = renderHook(() => useFilterBatch());

      // When
      act(() => {
        result.current.clearAndApply();
      });

      // Then — page is reset to 1
      expect(mockPush).toHaveBeenCalledTimes(1);
      const calledUrl: string = mockPush.mock.calls[0][0];
      expect(calledUrl).toContain("page=1");
    });
  });

});
