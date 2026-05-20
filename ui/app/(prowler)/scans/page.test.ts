import { readFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { describe, expect, it } from "vitest";

describe("scans page", () => {
  const currentDir = path.dirname(fileURLToPath(import.meta.url));
  const pagePath = path.join(currentDir, "page.tsx");
  const source = readFileSync(pagePath, "utf8");

  it("applies the selected tab state filters when fetching scans", () => {
    expect(source).toContain("getScanJobsTabFilters(tab)");
  });

  it("ignores state filters from the URL so the selected tab owns scan state", () => {
    expect(source).toContain("!isScanStateFilterKey(key)");
  });
});
