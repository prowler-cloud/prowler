import { readFileSync } from "node:fs";
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

  it("only passes sort to fetchFindingGroups when the user has an explicit sort param", () => {
    expect(source).toContain("...(encodedSort && { sort: encodedSort })");
  });

  it("normalizes scan filters with the required inserted_at params before fetching historical finding groups", () => {
    expect(source).toContain("resolveFindingScanDateFilters");
  });

  it("uses getLatestFindingGroups for non-date/scan queries and getFindingGroups for historical", () => {
    expect(source).toContain("hasDateOrScan");
    expect(source).toContain("getFindingGroups");
    expect(source).toContain("getLatestFindingGroups");
  });

  it("guards errors array access with a length check", () => {
    expect(source).toContain("errors?.length > 0");
  });

  it("resolves the id deep link through getFindingById and passes the expanded finding into the new drawer flow", () => {
    expect(source).toContain("const initialFindingId");
    expect(source).toContain("getFindingById(initialFindingId");
    expect(source).toContain("initialFinding={processedInitialFinding}");
  });
});
