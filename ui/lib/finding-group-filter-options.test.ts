import { describe, expect, it, vi } from "vitest";

import { getFindingGroupFilterOptions } from "./finding-group-filter-options";

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
    });
    expect(fetchFindingGroups).toHaveBeenNthCalledWith(2, {
      filters: { "filter[severity__in]": "high" },
      page: 2,
      pageSize: 100,
    });
    expect(options).toEqual([
      { checkId: "check-a", checkTitle: "Check A updated" },
      { checkId: "check-b", checkTitle: "Check B" },
    ]);
  });
});
