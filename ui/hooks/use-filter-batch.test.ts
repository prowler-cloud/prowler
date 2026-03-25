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

  // ── clearAll ───────────────────────────────────────────────────────────────

  describe("clearAll", () => {
    it("should clear all pending filters including provider and account keys", () => {
      // Given — user has pending provider, account, severity, and status filters
      setSearchParams({});
      const { result } = renderHook(() => useFilterBatch());

      act(() => {
        result.current.setPending("filter[provider_type__in]", [
          "aws",
          "azure",
        ]);
        result.current.setPending("filter[provider_id__in]", [
          "provider-uuid-1",
        ]);
        result.current.setPending("filter[severity__in]", ["critical"]);
        result.current.setPending("filter[status__in]", ["FAIL"]);
      });

      // Pre-condition — all filters are pending
      expect(
        result.current.pendingFilters["filter[provider_type__in]"],
      ).toEqual(["aws", "azure"]);
      expect(result.current.pendingFilters["filter[provider_id__in]"]).toEqual([
        "provider-uuid-1",
      ]);
      expect(result.current.pendingFilters["filter[severity__in]"]).toEqual([
        "critical",
      ]);

      // When
      act(() => {
        result.current.clearAll();
      });

      // Then — pending state must be TRULY EMPTY (no keys at all, not even with empty arrays)
      expect(result.current.pendingFilters).toEqual({});
      // getFilterValue normalises missing keys to [] so all selectors show "all selected"
      expect(
        result.current.getFilterValue("filter[provider_type__in]"),
      ).toEqual([]);
      expect(result.current.getFilterValue("filter[provider_id__in]")).toEqual(
        [],
      );
      expect(result.current.getFilterValue("filter[severity__in]")).toEqual([]);
      expect(result.current.getFilterValue("filter[status__in]")).toEqual([]);
    });

    it("should also clear provider/account keys that came from the URL (applied state)", () => {
      // Given — URL has provider and account filters applied
      setSearchParams({
        "filter[provider_type__in]": "aws",
        "filter[provider_id__in]": "provider-uuid-1",
        "filter[severity__in]": "critical",
      });
      const { result } = renderHook(() => useFilterBatch());

      // Pre-condition — filters are loaded from URL into pending
      expect(
        result.current.pendingFilters["filter[provider_type__in]"],
      ).toEqual(["aws"]);
      expect(result.current.pendingFilters["filter[provider_id__in]"]).toEqual([
        "provider-uuid-1",
      ]);

      // When
      act(() => {
        result.current.clearAll();
      });

      // Then — pending state must be truly empty (no keys, not { key: [] })
      expect(result.current.pendingFilters).toEqual({});
      // provider and account must be cleared even though they came from the URL
      expect(
        result.current.getFilterValue("filter[provider_type__in]"),
      ).toEqual([]);
      expect(result.current.getFilterValue("filter[provider_id__in]")).toEqual(
        [],
      );
      expect(result.current.getFilterValue("filter[severity__in]")).toEqual([]);
    });

    it("should mark hasChanges as true after clear when URL still has applied filters", () => {
      // Given — URL has filters applied
      setSearchParams({
        "filter[provider_type__in]": "aws",
        "filter[severity__in]": "critical",
      });
      const { result } = renderHook(() => useFilterBatch());

      // Pre-condition — no pending changes (matches URL)
      expect(result.current.hasChanges).toBe(false);

      // When — clear all
      act(() => {
        result.current.clearAll();
      });

      // Then — hasChanges must be true (pending is empty, URL still has filters)
      expect(result.current.hasChanges).toBe(true);
    });

    it("should NOT clear excluded keys (filter[search]) but DOES clear filter[muted]", () => {
      // Given — URL has search (excluded) plus muted and severity (both in batch)
      setSearchParams({
        "filter[search]": "my-search",
        "filter[muted]": "false",
        "filter[severity__in]": "critical",
      });
      const { result } = renderHook(() => useFilterBatch());

      // Pre-condition — muted and severity are in pendingFilters; search is excluded
      expect(result.current.pendingFilters["filter[search]"]).toBeUndefined();
      expect(result.current.pendingFilters["filter[muted]"]).toEqual(["false"]);

      // When
      act(() => {
        result.current.clearAll();
      });

      // Then — severity and muted are cleared; search remains excluded (undefined in pending)
      expect(result.current.getFilterValue("filter[severity__in]")).toEqual([]);
      expect(result.current.pendingFilters["filter[search]"]).toBeUndefined();
      // muted is a batch key, so it gets cleared by clearAll
      expect(result.current.pendingFilters["filter[muted]"]).toBeUndefined();
    });

    it("should clear applied URL filters even if they were explicitly removed from pendingFilters", () => {
      // This covers the edge case where pendingFilters diverged from URL state
      // (e.g., URL has provider filter but the key was removed from pending via removePending)
      setSearchParams({
        "filter[provider_type__in]": "gcp",
        "filter[severity__in]": "high",
      });
      const { result } = renderHook(() => useFilterBatch());

      // Remove the provider key from pending (diverge from URL state)
      act(() => {
        result.current.removePending("filter[provider_type__in]");
      });

      // Pre-condition — provider is gone from pending but still in URL
      expect(
        result.current.pendingFilters["filter[provider_type__in]"],
      ).toBeUndefined();

      // When — clearAll should clear BOTH pending keys AND applied URL keys
      act(() => {
        result.current.clearAll();
      });

      // Then — severity is cleared
      expect(result.current.getFilterValue("filter[severity__in]")).toEqual([]);
      // provider_type__in was in the URL (applied state), so clearAll must handle it
      expect(
        result.current.getFilterValue("filter[provider_type__in]"),
      ).toEqual([]);
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

  // ── clearKeys ─────────────────────────────────────────────────────────────

  describe("clearKeys", () => {
    it("should remove only specified keys and push URL", () => {
      // Given
      setSearchParams({});
      const { result } = renderHook(() => useFilterBatch());

      act(() => {
        result.current.setPending("filter[severity__in]", ["critical"]);
        result.current.setPending("filter[status__in]", ["FAIL"]);
        result.current.setPending("filter[region__in]", ["us-east-1"]);
      });

      // When
      act(() => {
        result.current.clearKeys(["filter[severity__in]"]);
      });

      // Then — severity is gone; status and region remain
      expect(
        result.current.pendingFilters["filter[severity__in]"],
      ).toBeUndefined();
      expect(result.current.pendingFilters["filter[status__in]"]).toEqual([
        "FAIL",
      ]);
      expect(result.current.pendingFilters["filter[region__in]"]).toEqual([
        "us-east-1",
      ]);

      // And the pushed URL contains the remaining keys but not severity
      expect(mockPush).toHaveBeenCalledTimes(1);
      const calledUrl: string = mockPush.mock.calls[0][0];
      expect(calledUrl).toContain("status");
      expect(calledUrl).toContain("region");
      expect(calledUrl).not.toContain("severity");
    });

    it("should accept keys without 'filter[' prefix", () => {
      // Given
      setSearchParams({});
      const { result } = renderHook(() => useFilterBatch());

      act(() => {
        result.current.setPending("filter[severity__in]", ["critical"]);
      });

      // When — pass key without filter[] wrapper
      act(() => {
        result.current.clearKeys(["severity__in"]);
      });

      // Then — severity is cleared
      expect(
        result.current.pendingFilters["filter[severity__in]"],
      ).toBeUndefined();
      expect(mockPush).toHaveBeenCalledTimes(1);
      const calledUrl: string = mockPush.mock.calls[0][0];
      expect(calledUrl).not.toContain("severity");
    });

    it("should preserve provider/account keys not in the cleared list", () => {
      // Given
      setSearchParams({});
      const { result } = renderHook(() => useFilterBatch());

      act(() => {
        result.current.setPending("filter[provider_type__in]", ["aws"]);
        result.current.setPending("filter[severity__in]", ["critical"]);
        result.current.setPending("filter[status__in]", ["FAIL"]);
      });

      // When — clear only severity and status; leave provider untouched
      act(() => {
        result.current.clearKeys([
          "filter[severity__in]",
          "filter[status__in]",
        ]);
      });

      // Then — provider_type__in is still in pending
      expect(
        result.current.pendingFilters["filter[provider_type__in]"],
      ).toEqual(["aws"]);
      expect(
        result.current.pendingFilters["filter[severity__in]"],
      ).toBeUndefined();
      expect(
        result.current.pendingFilters["filter[status__in]"],
      ).toBeUndefined();

      // And the pushed URL retains provider but not severity/status
      expect(mockPush).toHaveBeenCalledTimes(1);
      const calledUrl: string = mockPush.mock.calls[0][0];
      expect(calledUrl).toContain("provider_type__in");
      expect(calledUrl).not.toContain("severity");
      expect(calledUrl).not.toContain("status__in");
    });

    it("should apply defaultParams after clearing", () => {
      // Given
      setSearchParams({});
      const { result } = renderHook(() =>
        useFilterBatch({ defaultParams: { "filter[muted]": "false" } }),
      );

      act(() => {
        result.current.setPending("filter[severity__in]", ["critical"]);
      });

      // When
      act(() => {
        result.current.clearKeys(["filter[severity__in]"]);
      });

      // Then — defaultParam is present in the pushed URL
      expect(mockPush).toHaveBeenCalledTimes(1);
      const calledUrl: string = mockPush.mock.calls[0][0];
      expect(calledUrl).toContain("filter%5Bmuted%5D=false");
    });

    it("should reset pagination to page 1", () => {
      // Given — URL already has a page param
      mockSearchParamsValue = new URLSearchParams({
        "filter[severity__in]": "critical",
        page: "5",
      });
      const { result } = renderHook(() => useFilterBatch());

      // When
      act(() => {
        result.current.clearKeys(["filter[severity__in]"]);
      });

      // Then — page is reset to 1
      expect(mockPush).toHaveBeenCalledTimes(1);
      const calledUrl: string = mockPush.mock.calls[0][0];
      expect(calledUrl).toContain("page=1");
    });

    it("should handle empty keys array gracefully", () => {
      // Given
      setSearchParams({});
      const { result } = renderHook(() => useFilterBatch());

      act(() => {
        result.current.setPending("filter[severity__in]", ["critical"]);
      });

      // When — clear no keys at all
      act(() => {
        result.current.clearKeys([]);
      });

      // Then — pending is unchanged
      expect(result.current.pendingFilters["filter[severity__in]"]).toEqual([
        "critical",
      ]);

      // And router.push was still called (navigates with current state)
      expect(mockPush).toHaveBeenCalledTimes(1);
      const calledUrl: string = mockPush.mock.calls[0][0];
      expect(calledUrl).toContain("severity");
    });
  });
});
