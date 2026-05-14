import { readFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { describe, expect, it } from "vitest";

describe("AttackPathsPage", () => {
  const currentDir = path.dirname(fileURLToPath(import.meta.url));
  const filePath = path.join(currentDir, "attack-paths-page.tsx");
  const source = readFileSync(filePath, "utf8");

  it("keeps the page description without rendering a duplicate Attack Paths heading", () => {
    // Then
    expect(source).not.toContain(">\n          Attack Paths\n        </h2>");
    expect(source).toContain(
      "Select a scan, build a query, and visualize Attack Paths in your",
    );
  });
});
