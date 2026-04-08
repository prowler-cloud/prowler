import { readFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { describe, expect, it } from "vitest";

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
});
