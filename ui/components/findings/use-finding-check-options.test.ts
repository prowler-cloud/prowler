import { act, renderHook, waitFor } from "@testing-library/react";
import { beforeEach, describe, expect, it, vi } from "vitest";

const mocks = vi.hoisted(() => ({
  getFindingGroups: vi.fn(),
  getLatestFindingGroups: vi.fn(),
  getFindingGroupFilterOptions: vi.fn(),
}));

vi.mock("@/actions/finding-groups", () => ({
  getFindingGroups: mocks.getFindingGroups,
  getLatestFindingGroups: mocks.getLatestFindingGroups,
}));

vi.mock("@/lib/finding-group-filter-options", async (importOriginal) => ({
  ...(await importOriginal<
    typeof import("@/lib/finding-group-filter-options")
  >()),
  getFindingGroupFilterOptions: mocks.getFindingGroupFilterOptions,
}));

import { useFindingCheckOptions } from "./use-finding-check-options";

const filters: Record<string, string> = {
  "filter[severity__in]": "high",
  "filter[check_id__in]": "check-a",
};
const selected = [{ checkId: "check-a", checkTitle: "Check A" }];
const source = { filters, hasHistoricalData: false, initialOptions: selected };

describe("useFindingCheckOptions", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    mocks.getFindingGroupFilterOptions.mockResolvedValue([]);
  });

  it("should do nothing without a source", () => {
    // When
    const { result } = renderHook(() =>
      useFindingCheckOptions({ source: undefined }),
    );
    act(() => result.current.loadAll());

    // Then
    expect(mocks.getFindingGroupFilterOptions).not.toHaveBeenCalled();
    expect(result.current.options).toEqual([]);
  });

  it("should expose the selected titles without fetching anything", () => {
    // When
    const { result } = renderHook(() => useFindingCheckOptions({ source }));

    // Then
    expect(result.current.options).toEqual(selected);
    expect(mocks.getFindingGroupFilterOptions).not.toHaveBeenCalled();
  });

  it("should load every option once on first open and keep the selected titles", async () => {
    // Given
    mocks.getFindingGroupFilterOptions.mockResolvedValue([
      { checkId: "check-b", checkTitle: "Check B" },
    ]);
    const { result } = renderHook(() => useFindingCheckOptions({ source }));

    // When
    act(() => result.current.loadAll());
    expect(result.current.isLoading).toBe(true);
    act(() => result.current.loadAll());

    // Then
    await waitFor(() => expect(result.current.isLoading).toBe(false));
    expect(mocks.getFindingGroupFilterOptions).toHaveBeenCalledTimes(1);
    expect(mocks.getFindingGroupFilterOptions).toHaveBeenCalledWith({
      fetchFindingGroups: mocks.getLatestFindingGroups,
      filters,
    });
    expect(result.current.options).toEqual([
      ...selected,
      { checkId: "check-b", checkTitle: "Check B" },
    ]);
  });

  it("should use the historical finding groups fetcher when a date or scan filter is set", async () => {
    // Given
    const { result } = renderHook(() =>
      useFindingCheckOptions({
        source: { ...source, hasHistoricalData: true },
      }),
    );

    // When
    act(() => result.current.loadAll());

    // Then
    await waitFor(() =>
      expect(mocks.getFindingGroupFilterOptions).toHaveBeenCalledWith({
        fetchFindingGroups: mocks.getFindingGroups,
        filters,
      }),
    );
  });

  it("should forget loaded options when the surrounding filters change", async () => {
    // Given
    mocks.getFindingGroupFilterOptions.mockResolvedValue([
      { checkId: "check-b", checkTitle: "Check B" },
    ]);
    const { result, rerender } = renderHook(
      ({ filters }) =>
        useFindingCheckOptions({
          source: { filters, hasHistoricalData: false, initialOptions: [] },
        }),
      { initialProps: { filters } },
    );
    act(() => result.current.loadAll());
    await waitFor(() => expect(result.current.options).toHaveLength(1));

    // When
    rerender({ filters: { "filter[severity__in]": "low" } });

    // Then
    expect(result.current.options).toEqual([]);
    act(() => result.current.loadAll());
    await waitFor(() =>
      expect(mocks.getFindingGroupFilterOptions).toHaveBeenCalledTimes(2),
    );
  });

  it("should drop a load that finishes after the filters changed", async () => {
    // Given
    let resolveStale: (options: unknown) => void = () => undefined;
    mocks.getFindingGroupFilterOptions.mockImplementationOnce(
      () =>
        new Promise((resolve) => {
          resolveStale = resolve;
        }),
    );
    const { result, rerender } = renderHook(
      ({ filters }) =>
        useFindingCheckOptions({
          source: { filters, hasHistoricalData: false, initialOptions: [] },
        }),
      { initialProps: { filters } },
    );
    act(() => result.current.loadAll());
    rerender({ filters: { "filter[severity__in]": "low" } });

    // When
    await act(async () => {
      resolveStale([{ checkId: "stale", checkTitle: "Stale" }]);
    });

    // Then
    expect(result.current.options).toEqual([]);
    expect(result.current.isLoading).toBe(false);
    act(() => result.current.loadAll());
    await waitFor(() =>
      expect(mocks.getFindingGroupFilterOptions).toHaveBeenCalledTimes(2),
    );
  });

  it("should allow retrying after a failed load", async () => {
    // Given
    const consoleError = vi
      .spyOn(console, "error")
      .mockImplementation(() => undefined);
    mocks.getFindingGroupFilterOptions.mockRejectedValueOnce(new Error("boom"));
    const { result } = renderHook(() => useFindingCheckOptions({ source }));

    // When
    act(() => result.current.loadAll());
    await waitFor(() => expect(result.current.isLoading).toBe(false));
    act(() => result.current.loadAll());

    // Then
    expect(consoleError).toHaveBeenCalledTimes(1);
    expect(mocks.getFindingGroupFilterOptions).toHaveBeenCalledTimes(2);
    consoleError.mockRestore();
  });
});
