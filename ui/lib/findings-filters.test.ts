import { describe, expect, it } from "vitest";

import { applyDefaultMutedFilter, MUTED_FILTER } from "./findings-filters";

describe("applyDefaultMutedFilter", () => {
  it("injects filter[muted]=false when the caller has not set it", () => {
    const input: Record<string, string> = { "filter[status__in]": "FAIL" };
    const result = applyDefaultMutedFilter(input);

    expect(result["filter[muted]"]).toBe(MUTED_FILTER.EXCLUDE);
    expect(result["filter[status__in]"]).toBe("FAIL");
  });

  it("preserves an explicit filter[muted]=include opt-in from the checkbox", () => {
    const result = applyDefaultMutedFilter({
      "filter[muted]": MUTED_FILTER.INCLUDE,
    });

    expect(result["filter[muted]"]).toBe(MUTED_FILTER.INCLUDE);
  });

  it("preserves an explicit filter[muted]=false (no silent overwrite)", () => {
    const result = applyDefaultMutedFilter({
      "filter[muted]": MUTED_FILTER.EXCLUDE,
    });

    expect(result["filter[muted]"]).toBe(MUTED_FILTER.EXCLUDE);
  });

  it("does not mutate the input object", () => {
    const input = { "filter[status__in]": "FAIL" };
    applyDefaultMutedFilter(input);

    expect(input).not.toHaveProperty("filter[muted]");
  });

  it("returns a default-filled object when called with no caller filters", () => {
    const result = applyDefaultMutedFilter({} as Record<string, string>);

    expect(result["filter[muted]"]).toBe(MUTED_FILTER.EXCLUDE);
  });
});
