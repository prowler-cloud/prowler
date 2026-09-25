import { existsSync, readFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { describe, expect, it } from "vitest";

/**
 * Source-level assertions for the findings page.
 *
 * Directly importing page.tsx triggers deep transitive imports
 * (next-auth → next/server) that vitest cannot resolve without the
 * full Next.js build pipeline. These tests verify key architectural
 * invariants via source analysis instead.
 */
describe("findings page", () => {
  const currentDir = path.dirname(fileURLToPath(import.meta.url));
  const pagePath = path.join(currentDir, "page.tsx");
  const source = readFileSync(pagePath, "utf8");
  const filtersSectionSource = readFileSync(
    path.join(currentDir, "_components", "findings-filters-section.tsx"),
    "utf8",
  );

  it("only passes sort to fetchFindingGroups when the user has an explicit sort param", () => {
    expect(source).toContain("...(encodedSort && { sort: encodedSort })");
  });

  it("normalizes scan filters with the required inserted_at params before fetching historical finding groups", () => {
    expect(source).toContain("resolveFindingScanDateFilters");
  });

  it("uses resolved filters to choose getFindingGroups for historical queries and getLatestFindingGroups otherwise", () => {
    expect(source).toContain("hasHistoricalData");
    expect(source).toContain("hasDateOrScanFilter(filtersWithScanDates)");
    expect(source).toContain("hasDateOrScanFilter(filters)");
    expect(source).toContain("getFindingGroups");
    expect(source).toContain("getLatestFindingGroups");
  });

  it("defaults filter[muted]=false through the shared muted filter helper", () => {
    expect(source).toContain("applyDefaultMutedFilter(filtersWithScanDates)");
  });

  it("guards errors array access with a length check", () => {
    expect(source).toContain("errors?.length > 0");
  });

  it("applies the shared default muted filter so muted findings are hidden unless the caller opts in", () => {
    expect(source).toContain("applyDefaultMutedFilter");
  });

  it("renders a route loading state so the sidebar click paints immediately", () => {
    expect(existsSync(path.join(currentDir, "loading.tsx"))).toBe(true);
  });

  it("streams the filters behind their own Suspense boundary so the table does not wait for them", () => {
    expect(source).toContain("FindingsFiltersSkeleton");
    expect(source).toContain("FindingsFiltersSection");
    expect(source).not.toContain("getAllProviders");
    expect(source).not.toContain("getFindingGroupFilterOptions");
  });

  it("loads the scan date range per selected scan instead of waiting for the scans list", () => {
    expect(source).toContain("loadScan");
    expect(source).not.toContain("scans: scansData");
  });

  it("requests only completed scans with the fields the filters use", () => {
    expect(source).toContain('"filter[state]": "completed"');
    expect(source).toMatch(/fields:\s*\{[^}]*scans:/);
  });

  it("loads the check filter options lazily instead of walking finding groups before render", () => {
    expect(filtersSectionSource).not.toContain("getFindingGroupFilterOptions");
    expect(filtersSectionSource).toContain("checkOptionsSource");
  });
});
