import { readFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { describe, expect, it } from "vitest";

describe("column-get-scans", () => {
  const currentDir = path.dirname(fileURLToPath(import.meta.url));
  const filePath = path.join(currentDir, "column-get-scans.tsx");
  const source = readFileSync(filePath, "utf8");

  it("links scan findings to the historical finding-groups filters", () => {
    expect(source).toContain("filter[scan]=");
    expect(source).toContain("filter[inserted_at]=");
    expect(source).not.toContain("filter[scan__in]");
  });

  it("links the findings filter against the scan's completed_at (what the backend expects)", () => {
    expect(source).toMatch(/attributes:\s*{\s*completed_at\s*}/);
    expect(source).toMatch(/toLocalDateString\(completed_at\)/);
  });
});
