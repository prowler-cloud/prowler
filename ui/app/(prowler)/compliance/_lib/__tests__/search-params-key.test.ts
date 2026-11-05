import { describe, expect, it } from "vitest";

import { buildSearchParamsKey } from "../search-params-key";

describe("buildSearchParamsKey", () => {
  it("ignores table-state params so paginating or sorting never remounts the view", () => {
    const base = {
      complianceId: "comp-1",
      scanId: "scan-1",
      "filter[region__in]": "eu-west-1",
    };

    const withTableState = {
      ...base,
      page: "3",
      pageSize: "25",
      sort: "-severity",
    };

    expect(buildSearchParamsKey(withTableState)).toBe(
      buildSearchParamsKey(base),
    );
  });

  it("changes when a non-table param changes", () => {
    expect(
      buildSearchParamsKey({ complianceId: "comp-1", scanId: "scan-1" }),
    ).not.toBe(
      buildSearchParamsKey({ complianceId: "comp-1", scanId: "scan-2" }),
    );
  });
});
