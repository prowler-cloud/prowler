import { describe, expect, it } from "vitest";

import {
  applyDefaultMutedFilter,
  applyFailNonMutedFilters,
  FAIL_FILTER_VALUE,
  includesMutedFindings,
  MUTED_FILTER,
  NEW_DELTA_FILTER_VALUE,
  splitCsvFilterValues,
} from "./findings-filters";

describe("filter value constants", () => {
  it("exposes wire-format values exactly as the API expects", () => {
    expect(FAIL_FILTER_VALUE).toBe("FAIL");
    expect(NEW_DELTA_FILTER_VALUE).toBe("new");
    expect(MUTED_FILTER.EXCLUDE).toBe("false");
    expect(MUTED_FILTER.INCLUDE).toBe("include");
  });
});

describe("applyFailNonMutedFilters", () => {
  it("sets filter[status__in]=FAIL and filter[muted]=false", () => {
    const params = new URLSearchParams();

    applyFailNonMutedFilters(params);

    expect(params.get("filter[status__in]")).toBe("FAIL");
    expect(params.get("filter[muted]")).toBe("false");
  });

  it("overrides pre-existing values so the drill-down is idempotent", () => {
    const params = new URLSearchParams(
      "filter[status__in]=PASS&filter[muted]=include",
    );

    applyFailNonMutedFilters(params);

    expect(params.get("filter[status__in]")).toBe("FAIL");
    expect(params.get("filter[muted]")).toBe("false");
  });

  it("preserves unrelated params", () => {
    const params = new URLSearchParams(
      "filter[provider_id__in]=abc&sort=-severity",
    );

    applyFailNonMutedFilters(params);

    expect(params.get("filter[provider_id__in]")).toBe("abc");
    expect(params.get("sort")).toBe("-severity");
  });
});

describe("applyDefaultMutedFilter", () => {
  it("adds filter[muted]=false when the filter is absent", () => {
    expect(applyDefaultMutedFilter({ "filter[status__in]": "FAIL" })).toEqual({
      "filter[muted]": "false",
      "filter[status__in]": "FAIL",
    });
  });

  it("preserves an explicit include value from the caller", () => {
    expect(
      applyDefaultMutedFilter({
        "filter[muted]": "include",
        "filter[status__in]": "FAIL",
      }),
    ).toEqual({
      "filter[muted]": "include",
      "filter[status__in]": "FAIL",
    });
  });
});

describe("splitCsvFilterValues", () => {
  it("returns an empty array when the value is undefined", () => {
    expect(splitCsvFilterValues(undefined)).toEqual([]);
  });

  it("splits a CSV string and trims whitespace", () => {
    expect(splitCsvFilterValues("FAIL, PASS ,MANUAL")).toEqual([
      "FAIL",
      "PASS",
      "MANUAL",
    ]);
  });

  it("flattens repeated array values (Next.js can surface them this way)", () => {
    expect(splitCsvFilterValues(["FAIL", "PASS,MANUAL"])).toEqual([
      "FAIL",
      "PASS",
      "MANUAL",
    ]);
  });

  it("drops empty tokens produced by stray commas", () => {
    expect(splitCsvFilterValues("FAIL,,PASS,")).toEqual(["FAIL", "PASS"]);
  });
});

describe("includesMutedFindings", () => {
  it("returns false when filter[muted] is absent", () => {
    expect(includesMutedFindings({})).toBe(false);
  });

  it("returns true for the literal 'include' sentinel", () => {
    expect(includesMutedFindings({ "filter[muted]": "include" })).toBe(true);
  });

  it("returns false for 'false' (the exclude value)", () => {
    expect(includesMutedFindings({ "filter[muted]": "false" })).toBe(false);
  });

  it("returns true when 'include' appears anywhere in an array value", () => {
    expect(
      includesMutedFindings({ "filter[muted]": ["false", "include"] }),
    ).toBe(true);
  });
});
