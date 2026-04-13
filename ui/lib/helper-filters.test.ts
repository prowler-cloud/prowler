import { describe, expect, it } from "vitest";

import { hasDateFilter, hasDateOrScanFilter } from "./helper-filters";

describe("hasDateOrScanFilter", () => {
  it("returns true for scan filters", () => {
    expect(hasDateOrScanFilter({ "filter[scan__in]": "scan-1" })).toBe(true);
  });

  it("returns true for inserted_at filters", () => {
    expect(
      hasDateOrScanFilter({ "filter[inserted_at__gte]": "2026-04-01" }),
    ).toBe(true);
  });
});

describe("hasDateFilter", () => {
  it("returns true for inserted_at filters", () => {
    expect(hasDateFilter({ "filter[inserted_at__lte]": "2026-04-07" })).toBe(
      true,
    );
  });

  it("returns false for scan filters only", () => {
    expect(hasDateFilter({ "filter[scan__in]": "scan-1" })).toBe(false);
  });
});
