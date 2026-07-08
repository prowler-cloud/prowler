import { act, renderHook } from "@testing-library/react";
import { beforeEach, describe, expect, it, vi } from "vitest";

import { FINDING_TRIAGE_STATUS } from "@/types/findings-triage";

import { useRequirementFindings } from "./use-requirement-findings";

const findingsActionsMock = vi.hoisted(() => ({
  getFindings: vi.fn(),
}));

vi.mock("@/actions/findings", () => findingsActionsMock);

function makeFindingsResponse() {
  return {
    data: [
      {
        id: "finding-1",
        attributes: { muted: false, status: "FAIL" },
        triage: {
          findingId: "finding-1",
          findingUid: "uid-1",
          triageId: "triage-1",
          notesCount: 0,
          status: FINDING_TRIAGE_STATUS.UNDER_REVIEW,
          label: "Under Review",
          hasVisibleNote: false,
          isMuted: false,
          canEdit: true,
          billingHref: "https://prowler.com/pricing",
        },
        relationships: {
          scan: { data: { id: "scan-1" } },
          resources: { data: [{ id: "resource-1" }] },
        },
      },
    ],
    included: [
      {
        type: "scans",
        id: "scan-1",
        relationships: { provider: { data: { id: "provider-1" } } },
      },
      { type: "resources", id: "resource-1" },
      { type: "providers", id: "provider-1" },
    ],
    meta: { pagination: { count: 1, pages: 1 } },
  };
}

function defaultOptions(overrides?: Record<string, unknown>) {
  return {
    enabled: true,
    checkIds: ["check_1", "check_2"],
    scanId: "scan-1",
    pageNumber: "1",
    pageSize: "10",
    sort: "+severity",
    region: "",
    mutedFilter: "false",
    ...overrides,
  };
}

async function flushAsync() {
  await act(async () => {
    await new Promise((resolve) => setTimeout(resolve, 0));
  });
}

// The cross-provider fan-out fires, per scan, one row-page request plus two
// count-only requests (``filter[status__in]`` PASS / FAIL, used only for their
// ``meta.pagination.count``). Route the mock by scan id + status so the tests
// stay independent of call ordering.
function mockCrossProviderFindings(
  config: Record<string, { main: unknown; pass?: number; fail?: number }>,
) {
  findingsActionsMock.getFindings.mockImplementation(
    async ({ filters }: { filters: Record<string, string> }) => {
      const scan = filters["filter[scan]"];
      const status = filters["filter[status__in]"];
      const entry = config[scan];
      if (!entry) return undefined;
      if (status === "PASS")
        return {
          data: [],
          meta: { pagination: { count: entry.pass ?? 0, pages: 1 } },
        };
      if (status === "FAIL")
        return {
          data: [],
          meta: { pagination: { count: entry.fail ?? 0, pages: 1 } },
        };
      return entry.main;
    },
  );
}

describe("useRequirementFindings", () => {
  beforeEach(() => {
    findingsActionsMock.getFindings.mockReset();
    findingsActionsMock.getFindings.mockResolvedValue(makeFindingsResponse());
  });

  it("should fetch findings with the requirement filters and strip the sort plus sign", async () => {
    // Given / When
    renderHook(() => useRequirementFindings(defaultOptions()));
    await flushAsync();

    // Then
    expect(findingsActionsMock.getFindings).toHaveBeenCalledTimes(1);
    expect(findingsActionsMock.getFindings).toHaveBeenCalledWith({
      filters: {
        "filter[check_id__in]": "check_1,check_2",
        "filter[scan]": "scan-1",
        "filter[muted]": "false",
      },
      page: 1,
      pageSize: 10,
      sort: "severity",
    });
  });

  it("should expand findings with their included scan, resource, and provider", async () => {
    // Given / When
    const { result } = renderHook(() =>
      useRequirementFindings(defaultOptions()),
    );
    await flushAsync();

    // Then
    const [expanded] = result.current.expandedFindings;
    expect(expanded.relationships).toEqual({
      scan: expect.objectContaining({ id: "scan-1" }),
      resource: expect.objectContaining({ id: "resource-1" }),
      provider: expect.objectContaining({ id: "provider-1" }),
    });
    expect(result.current.findings?.meta?.pagination?.count).toBe(1);
  });

  it("should not fetch when disabled or without check ids", async () => {
    // Given / When
    renderHook(() =>
      useRequirementFindings(defaultOptions({ enabled: false })),
    );
    renderHook(() => useRequirementFindings(defaultOptions({ checkIds: [] })));
    await flushAsync();

    // Then
    expect(findingsActionsMock.getFindings).not.toHaveBeenCalled();
  });

  it("should not report loading when the fetch is disabled", async () => {
    // Given / When
    const disabled = renderHook(() =>
      useRequirementFindings(defaultOptions({ enabled: false })),
    );
    const withoutChecks = renderHook(() =>
      useRequirementFindings(defaultOptions({ checkIds: [] })),
    );
    await flushAsync();

    // Then — a skipped fetch must not look like a pending one.
    expect(disabled.result.current.isLoading).toBe(false);
    expect(withoutChecks.result.current.isLoading).toBe(false);
  });

  it("should report loading until the fetch settles", async () => {
    // Given
    let resolveFetch: (value: unknown) => void = () => {};
    findingsActionsMock.getFindings.mockImplementationOnce(
      () => new Promise((resolve) => (resolveFetch = resolve)),
    );

    // When
    const { result } = renderHook(() =>
      useRequirementFindings(defaultOptions()),
    );

    // Then
    expect(result.current.isLoading).toBe(true);

    // When
    act(() => {
      resolveFetch(makeFindingsResponse());
    });
    await flushAsync();

    // Then
    expect(result.current.isLoading).toBe(false);
  });

  it("should expose an error and stop loading when the fetch fails", async () => {
    // Given
    const consoleErrorSpy = vi
      .spyOn(console, "error")
      .mockImplementation(() => {});
    findingsActionsMock.getFindings.mockRejectedValue(
      new Error("network down"),
    );

    // When
    const { result } = renderHook(() =>
      useRequirementFindings(defaultOptions()),
    );
    await flushAsync();

    // Then — the caller can render an error state instead of a skeleton.
    expect(result.current.error).toBe("Could not load findings.");
    expect(result.current.isLoading).toBe(false);
    expect(result.current.findings).toBeNull();

    consoleErrorSpy.mockRestore();
  });

  it("should clear the error and recover on reload", async () => {
    // Given: first fetch fails, retry succeeds
    const consoleErrorSpy = vi
      .spyOn(console, "error")
      .mockImplementation(() => {});
    findingsActionsMock.getFindings
      .mockRejectedValueOnce(new Error("network down"))
      .mockResolvedValueOnce(makeFindingsResponse());

    const { result } = renderHook(() =>
      useRequirementFindings(defaultOptions()),
    );
    await flushAsync();
    expect(result.current.error).toBe("Could not load findings.");

    // When
    act(() => {
      result.current.reload();
    });
    await flushAsync();

    // Then
    expect(result.current.error).toBeNull();
    expect(result.current.findings).not.toBeNull();

    consoleErrorSpy.mockRestore();
  });

  it("should not refetch when only the checkIds array identity changes", async () => {
    // Given
    const { rerender } = renderHook((props) => useRequirementFindings(props), {
      initialProps: defaultOptions(),
    });
    await flushAsync();

    // When: same values, fresh array identity (parent re-render)
    rerender(defaultOptions());
    await flushAsync();

    // Then
    expect(findingsActionsMock.getFindings).toHaveBeenCalledTimes(1);
  });

  it("should refetch when a query parameter changes", async () => {
    // Given
    const { rerender } = renderHook((props) => useRequirementFindings(props), {
      initialProps: defaultOptions(),
    });
    await flushAsync();

    // When
    rerender(defaultOptions({ pageNumber: "2" }));
    await flushAsync();

    // Then
    expect(findingsActionsMock.getFindings).toHaveBeenCalledTimes(2);
    expect(findingsActionsMock.getFindings).toHaveBeenLastCalledWith(
      expect.objectContaining({ page: 2 }),
    );
  });

  it("should refetch on reload keeping previous data visible meanwhile", async () => {
    // Given
    const { result } = renderHook(() =>
      useRequirementFindings(defaultOptions()),
    );
    await flushAsync();

    // When
    act(() => {
      result.current.reload();
    });

    // Then: previous data is not cleared while the refetch is in flight
    expect(result.current.findings).not.toBeNull();
    await flushAsync();
    expect(findingsActionsMock.getFindings).toHaveBeenCalledTimes(2);
  });

  it("should patch the matching row triage optimistically", async () => {
    // Given
    const { result } = renderHook(() =>
      useRequirementFindings(defaultOptions()),
    );
    await flushAsync();

    // When
    act(() => {
      result.current.patchTriageUpdate({
        findingId: "finding-1",
        findingUid: "uid-1",
        triageId: "triage-1",
        notesCount: 0,
        status: FINDING_TRIAGE_STATUS.REMEDIATING,
        previousStatus: FINDING_TRIAGE_STATUS.UNDER_REVIEW,
        isMuted: false,
      });
    });

    // Then
    expect(result.current.expandedFindings[0]?.triage).toEqual(
      expect.objectContaining({
        status: FINDING_TRIAGE_STATUS.REMEDIATING,
        label: "Remediating",
      }),
    );
  });

  it("fans out a row-page fetch plus count-only PASS/FAIL per scan and merges the counts in cross-provider mode", async () => {
    // Given: two providers, one scan each, with disjoint check sets.
    findingsActionsMock.getFindings.mockReset();
    mockCrossProviderFindings({
      "scan-a": {
        main: {
          data: [
            {
              id: "finding-a",
              attributes: { status: "FAIL" },
              relationships: { scan: { data: { id: "scan-a" } } },
            },
          ],
          included: [{ type: "scans", id: "scan-a" }],
          meta: { pagination: { count: 1, pages: 1 } },
        },
        pass: 0,
        fail: 1,
      },
      "scan-b": {
        main: {
          data: [
            {
              id: "finding-b",
              attributes: { status: "PASS" },
              relationships: { scan: { data: { id: "scan-b" } } },
            },
          ],
          included: [{ type: "scans", id: "scan-b" }],
          meta: { pagination: { count: 2, pages: 1 } },
        },
        pass: 2,
        fail: 0,
      },
    });

    // When
    const { result } = renderHook(() =>
      useRequirementFindings(
        defaultOptions({
          isCrossProvider: true,
          scanIdsByProvider: { aws: ["scan-a"], azure: ["scan-b"] },
          checkIdsByProvider: { aws: ["check_a"], azure: ["check_b"] },
          scopeSignature: "scope-1",
        }),
      ),
    );
    await flushAsync();

    // Then: three requests per scan (row page + PASS count + FAIL count) → 6.
    expect(findingsActionsMock.getFindings).toHaveBeenCalledTimes(6);
    // The row-page request is scoped to that provider's checks, no status filter.
    expect(findingsActionsMock.getFindings).toHaveBeenCalledWith(
      expect.objectContaining({
        filters: expect.objectContaining({
          "filter[scan]": "scan-a",
          "filter[check_id__in]": "check_a",
        }),
        pageSize: 10,
      }),
    );
    // And a count-only PASS request (page size 1) for the same scan+checks.
    expect(findingsActionsMock.getFindings).toHaveBeenCalledWith(
      expect.objectContaining({
        filters: expect.objectContaining({
          "filter[scan]": "scan-a",
          "filter[check_id__in]": "check_a",
          "filter[status__in]": "PASS",
        }),
        pageSize: 1,
      }),
    );
    // Only the row-page responses feed the merge: rows concatenated, counts summed.
    expect(result.current.findings?.data).toHaveLength(2);
    expect(result.current.findings?.meta?.pagination?.count).toBe(3);
    // Exact per-scan pass/fail come from the count-only responses, not the rows.
    expect(result.current.crossProviderScanMeta["scan-a"]).toEqual(
      expect.objectContaining({ count: 1, pages: 1, pass: 0, fail: 1 }),
    );
    expect(result.current.crossProviderScanMeta["scan-b"]).toEqual(
      expect.objectContaining({ count: 2, pages: 1, pass: 2, fail: 0 }),
    );
  });

  it("takes the worst-case page count across scans so pagination reaches every tail", async () => {
    findingsActionsMock.getFindings.mockReset();
    mockCrossProviderFindings({
      "scan-a": {
        // AWS spans many pages…
        main: {
          data: [
            {
              id: "finding-a",
              attributes: { status: "FAIL", severity: "high" },
              relationships: { scan: { data: { id: "scan-a" } } },
            },
          ],
          included: [{ type: "scans", id: "scan-a" }],
          meta: { pagination: { count: 30, pages: 3 } },
        },
        pass: 10,
        fail: 20,
      },
      "scan-b": {
        // …Azure fits in one.
        main: {
          data: [
            {
              id: "finding-b",
              attributes: { status: "PASS", severity: "low" },
              relationships: { scan: { data: { id: "scan-b" } } },
            },
          ],
          included: [{ type: "scans", id: "scan-b" }],
          meta: { pagination: { count: 5, pages: 1 } },
        },
        pass: 5,
        fail: 0,
      },
    });

    const { result } = renderHook(() =>
      useRequirementFindings(
        defaultOptions({
          isCrossProvider: true,
          scanIdsByProvider: { aws: ["scan-a"], azure: ["scan-b"] },
          checkIdsByProvider: { aws: ["check_a"], azure: ["check_b"] },
          scopeSignature: "scope-pages",
        }),
      ),
    );
    await flushAsync();

    // The merged envelope must expose 3 pages (not the hardcoded 1) so the
    // table's Next button stays enabled and AWS's later pages are reachable.
    expect(result.current.findings?.meta?.pagination?.pages).toBe(3);
    expect(result.current.findings?.meta?.pagination?.count).toBe(35);
    // Pass/fail are exact even though AWS is paginated — they come from the
    // count-only fetches, not the single loaded page.
    expect(result.current.crossProviderScanMeta["scan-a"]).toEqual(
      expect.objectContaining({ pages: 3, pass: 10, fail: 20 }),
    );
  });

  it("globally re-sorts the merged rows by the active sort (FAIL/critical first)", async () => {
    findingsActionsMock.getFindings.mockReset();
    // Scan A returns a PASS/low row; scan B a FAIL/critical row. Concatenation
    // alone would list A before B and contradict the FAIL-first sort.
    mockCrossProviderFindings({
      "scan-a": {
        main: {
          data: [
            {
              id: "finding-pass",
              attributes: { status: "PASS", severity: "low" },
              relationships: { scan: { data: { id: "scan-a" } } },
            },
          ],
          included: [{ type: "scans", id: "scan-a" }],
          meta: { pagination: { count: 1, pages: 1 } },
        },
      },
      "scan-b": {
        main: {
          data: [
            {
              id: "finding-fail",
              attributes: { status: "FAIL", severity: "critical" },
              relationships: { scan: { data: { id: "scan-b" } } },
            },
          ],
          included: [{ type: "scans", id: "scan-b" }],
          meta: { pagination: { count: 1, pages: 1 } },
        },
      },
    });

    const { result } = renderHook(() =>
      useRequirementFindings(
        defaultOptions({
          // Family A default: status,severity,-inserted_at → FAIL/critical first.
          sort: "status,severity,-inserted_at",
          isCrossProvider: true,
          scanIdsByProvider: { aws: ["scan-a"], azure: ["scan-b"] },
          checkIdsByProvider: { aws: ["check_a"], azure: ["check_b"] },
          scopeSignature: "scope-sort",
        }),
      ),
    );
    await flushAsync();

    expect(result.current.findings?.data?.map((f) => f.id)).toEqual([
      "finding-fail",
      "finding-pass",
    ]);
  });

  it("should not fetch in cross-provider mode when no scans contribute", async () => {
    // Given / When
    renderHook(() =>
      useRequirementFindings(
        defaultOptions({
          isCrossProvider: true,
          scanIdsByProvider: {},
          checkIdsByProvider: {},
          scopeSignature: "empty",
        }),
      ),
    );
    await flushAsync();

    // Then
    expect(findingsActionsMock.getFindings).not.toHaveBeenCalled();
  });

  it("should ignore stale responses after the query changes", async () => {
    // Given: first request resolves late, second resolves immediately
    let resolveFirst: (value: unknown) => void = () => {};
    const staleResponse = {
      ...makeFindingsResponse(),
      meta: { pagination: { count: 99, pages: 9 } },
    };
    findingsActionsMock.getFindings
      .mockImplementationOnce(
        () => new Promise((resolve) => (resolveFirst = resolve)),
      )
      .mockResolvedValueOnce(makeFindingsResponse());

    const { result, rerender } = renderHook(
      (props) => useRequirementFindings(props),
      { initialProps: defaultOptions() },
    );

    // When: the query changes before the first request settles
    rerender(defaultOptions({ pageNumber: "2" }));
    await flushAsync();
    act(() => {
      resolveFirst(staleResponse);
    });
    await flushAsync();

    // Then: the stale response never overwrites the fresh one
    expect(result.current.findings?.meta?.pagination?.count).toBe(1);
  });
});
