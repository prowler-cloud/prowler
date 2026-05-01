import { readFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { describe, expect, it } from "vitest";

describe("client accordion content", () => {
  const currentDir = path.dirname(fileURLToPath(import.meta.url));
  const filePath = path.join(currentDir, "client-accordion-content.tsx");
  const source = readFileSync(filePath, "utf8");

  it("uses the shared standalone finding columns instead of the legacy findings columns", () => {
    expect(source).toContain("getStandaloneFindingColumns");
    expect(source).not.toContain("getColumnFindings");
  });
});
