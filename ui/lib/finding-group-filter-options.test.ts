import { describe, expect, it, vi } from "vitest";

import {
  getFindingGroupFilterOptions,
  getSelectedFindingCheckOptions,
} from "./finding-group-filter-options";

function makeResponse(
  pageCount: number,
  groups: Array<{ id: string; title: string }>,
) {
  return {
    data: groups.map(({ id, title }) => ({
      type: "finding-groups",
      id,
      attributes: {
        check_id: id,
        check_title: title,
        check_description: null,
        severity: "high",
        status: "FAIL",
        impacted_providers: [],
        resources_total: 1,
        resources_fail: 1,
        pass_count: 0,
        fail_count: 1,
        muted_count: 0,
        new_count: 0,
        changed_count: 0,
        first_seen_at: null,
        last_seen_at: null,
        failing_since: null,
      },
    })),
    meta: { pagination: { pages: pageCount } },
  };
}

describe("getFindingGroupFilterOptions", () => {
  it("loads every page without applying the filter's own selection", async () => {
    // Given
    const fetchFindingGroups = vi
      .fn()
      .mockResolvedValueOnce(
        makeResponse(2, [{ id: "check-a", title: "Check A" }]),
      )
      .mockResolvedValueOnce(
        makeResponse(2, [
          { id: "check-a", title: "Check A updated" },
          { id: "check-b", title: "Check B" },
        ]),
      );

    // When
    const options = await getFindingGroupFilterOptions({
      fetchFindingGroups,
      filters: {
        "filter[check_id__in]": "check-a",
        "filter[severity__in]": "high",
      },
    });

    // Then
    expect(fetchFindingGroups).toHaveBeenNthCalledWith(1, {
      filters: { "filter[severity__in]": "high" },
      page: 1,
      pageSize: 100,
      sort: "check_id",
    });
    expect(fetchFindingGroups).toHaveBeenNthCalledWith(2, {
      filters: { "filter[severity__in]": "high" },
      page: 2,
      pageSize: 100,
      sort: "check_id",
    });
    expect(options).toEqual([
      { checkId: "check-a", checkTitle: "Check A updated" },
      { checkId: "check-b", checkTitle: "Check B" },
    ]);
  });

  it("requests the remaining pages concurrently once the page count is known", async () => {
    // Given
    const pending: Array<(value: unknown) => void> = [];
    const fetchFindingGroups = vi.fn(
      ({ page }: { page: number }) =>
        new Promise((resolve) => {
          if (page === 1) {
            resolve(makeResponse(3, [{ id: "check-a", title: "Check A" }]));
            return;
          }
          pending.push(resolve);
        }),
    );

    // When
    const optionsPromise = getFindingGroupFilterOptions({
      fetchFindingGroups,
      filters: {},
    });
    await vi.waitFor(() => expect(fetchFindingGroups).toHaveBeenCalledTimes(3));
    pending[0](makeResponse(3, [{ id: "check-b", title: "Check B" }]));
    pending[1](makeResponse(3, [{ id: "check-c", title: "Check C" }]));
    const options = await optionsPromise;

    // Then
    expect(
      fetchFindingGroups.mock.calls.map(([params]) => params.page),
    ).toEqual([1, 2, 3]);
    expect(options.map((option) => option.checkId)).toEqual([
      "check-a",
      "check-b",
      "check-c",
    ]);
  });

  it("stops after the first page when the response has no pagination", async () => {
    // Given
    const fetchFindingGroups = vi.fn().mockResolvedValue(undefined);

    // When
    const options = await getFindingGroupFilterOptions({
      fetchFindingGroups,
      filters: {},
    });

    // Then
    expect(fetchFindingGroups).toHaveBeenCalledTimes(1);
    expect(options).toEqual([]);
  });

  it("caps how many option pages are requested at the same time", async () => {
    // Given
    const resolvers: Array<() => void> = [];
    const fetchFindingGroups = vi.fn(({ page }: { page: number }) => {
      const response = makeResponse(12, [
        { id: `check-${page}`, title: `Check ${page}` },
      ]);
      if (page === 1) return Promise.resolve(response);
      return new Promise((resolve) => {
        resolvers.push(() => resolve(response));
      });
    });

    // When
    const optionsPromise = getFindingGroupFilterOptions({
      fetchFindingGroups,
      filters: {},
    });
    await vi.waitFor(() => expect(fetchFindingGroups).toHaveBeenCalledTimes(5));
    await new Promise((resolve) => setTimeout(resolve, 0));
    expect(fetchFindingGroups).toHaveBeenCalledTimes(5);
    while (fetchFindingGroups.mock.calls.length < 12 || resolvers.length > 0) {
      await vi.waitFor(() => expect(resolvers.length).toBeGreaterThan(0));
      resolvers.pop()?.();
    }
    const options = await optionsPromise;

    // Then
    expect(fetchFindingGroups).toHaveBeenCalledTimes(12);
    expect(options.map((option) => option.checkId)).toEqual(
      Array.from({ length: 12 }, (_, index) => `check-${index + 1}`),
    );
  });
});

describe("getSelectedFindingCheckOptions", () => {
  it("resolves titles for the selected checks in one request without the filter's own selection", async () => {
    // Given
    const fetchFindingGroups = vi
      .fn()
      .mockResolvedValue(
        makeResponse(1, [{ id: "check-a", title: "Check A" }]),
      );

    // When
    const options = await getSelectedFindingCheckOptions({
      fetchFindingGroups,
      filters: {
        "filter[check_id__in]": "check-a",
        "filter[severity__in]": "high",
      },
      selectedCheckIds: ["check-a", "check-b", "check-a"],
    });

    // Then
    expect(fetchFindingGroups).toHaveBeenCalledTimes(1);
    expect(fetchFindingGroups).toHaveBeenCalledWith({
      filters: {
        "filter[severity__in]": "high",
        "filter[check_id__in]": "check-a,check-b",
      },
      page: 1,
      pageSize: 100,
      sort: "check_id",
    });
    expect(options).toEqual([{ checkId: "check-a", checkTitle: "Check A" }]);
  });

  it("does not request anything when no check is selected", async () => {
    // Given
    const fetchFindingGroups = vi.fn();

    // When
    const options = await getSelectedFindingCheckOptions({
      fetchFindingGroups,
      filters: {},
      selectedCheckIds: [],
    });

    // Then
    expect(fetchFindingGroups).not.toHaveBeenCalled();
    expect(options).toEqual([]);
  });
});
