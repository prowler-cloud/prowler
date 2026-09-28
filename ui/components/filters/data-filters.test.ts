import { describe, expect, it } from "vitest";

import { FILTER_FIELD, FILTER_SELECTION_MODE } from "@/types/filters";

import { filterFindings } from "./data-filters";

describe("filterFindings", () => {
  it("configures delta as a single-select filter", () => {
    const deltaFilter = filterFindings.find(
      (filter) => filter.key === FILTER_FIELD.DELTA,
    );

    expect(deltaFilter).toMatchObject({
      selectionMode: FILTER_SELECTION_MODE.SINGLE,
      values: ["new", "changed"],
    });
  });
});
