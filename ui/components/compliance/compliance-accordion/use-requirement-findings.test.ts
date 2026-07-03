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
