import { act, renderHook } from "@testing-library/react";
import { beforeEach, describe, expect, it, vi } from "vitest";

const { getFindingById } = vi.hoisted(() => ({ getFindingById: vi.fn() }));
vi.mock("@/actions/findings", () => ({ getFindingById }));
// The real helper sits behind the server-only `@/lib` barrel.
vi.mock("@/lib/finding-detail", () => ({
  expandFindingWithRelationships: (response?: { data?: unknown }) =>
    response?.data ?? null,
}));

import { useFindingDetails } from "./use-finding-details";

const deferred = () => {
  let resolve!: (value: unknown) => void;
  const promise = new Promise((done) => {
    resolve = done;
  });
  return { promise, resolve };
};

describe("useFindingDetails", () => {
  beforeEach(() => {
    getFindingById.mockReset();
  });

  it("keeps a slow earlier lookup from overwriting a newer one", async () => {
    // Given: lookup A is still pending when lookup B starts
    const first = deferred();
    const second = deferred();
    getFindingById
      .mockReturnValueOnce(first.promise)
      .mockReturnValueOnce(second.promise);
    const { result } = renderHook(() => useFindingDetails());
    act(() => {
      void result.current.navigateToFinding("a");
    });
    act(() => {
      void result.current.navigateToFinding("b");
    });

    // When: A answers after B started
    await act(async () => first.resolve({ data: { id: "a" } }));

    // Then: B is still loading and A is dropped
    expect(result.current.findingDetails).toBeNull();
    expect(result.current.findingDetailLoading).toBe(true);

    // When
    await act(async () => second.resolve({ data: { id: "b" } }));

    // Then
    expect(result.current.findingDetails).toEqual({ id: "b" });
    expect(result.current.findingDetailLoading).toBe(false);
  });

  it("drops a lookup that answers after a reset", async () => {
    // Given
    const pending = deferred();
    getFindingById.mockReturnValueOnce(pending.promise);
    const { result } = renderHook(() => useFindingDetails());
    act(() => {
      void result.current.navigateToFinding("a");
    });

    // When: the finding closes, then its lookup answers
    act(() => result.current.resetFindingDetails());
    await act(async () => pending.resolve({ data: { id: "a" } }));

    // Then
    expect(result.current.findingDetails).toBeNull();
    expect(result.current.findingDetailLoading).toBe(false);
  });
});
