import { readFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { describe, expect, it } from "vitest";

describe("Compliance overview page", () => {
  const currentDir = path.dirname(fileURLToPath(import.meta.url));
  const filePath = path.join(currentDir, "page.tsx");
  const source = readFileSync(filePath, "utf8");

  it("delegates client-side search to ComplianceOverviewGrid", () => {
    expect(source).toContain("ComplianceOverviewGrid");
    expect(source).not.toContain("filter[search]");
  });
});
