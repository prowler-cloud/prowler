import { readFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { describe, expect, it } from "vitest";

describe("findings view overview SSR", () => {
  const currentDir = path.dirname(fileURLToPath(import.meta.url));
  const filePath = path.join(currentDir, "findings-view.ssr.tsx");
  const source = readFileSync(filePath, "utf8");

  it("uses the non-legacy latest findings columns", () => {
    expect(source).toContain("ColumnLatestFindings");
    expect(source).not.toContain("ColumnNewFindingsToDate");
  });
});
