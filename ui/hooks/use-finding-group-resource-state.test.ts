import { readFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { describe, expect, it } from "vitest";

describe("useFindingGroupResourceState", () => {
  const currentDir = path.dirname(fileURLToPath(import.meta.url));
  const filePath = path.join(currentDir, "use-finding-group-resource-state.ts");
  const source = readFileSync(filePath, "utf8");

  it("defaults drill-down resource loading through the shared muted filter helper", () => {
    expect(source).toContain("applyDefaultMutedFilter(filters)");
  });

  it("enables muted findings only for the finding-group resource drawer", () => {
    expect(source).toContain("includeMutedInOtherFindings: true");
  });
});
