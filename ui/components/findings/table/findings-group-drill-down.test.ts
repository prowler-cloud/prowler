import { readFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { describe, expect, it } from "vitest";

describe("findings group drill down", () => {
  const currentDir = path.dirname(fileURLToPath(import.meta.url));
  const filePath = path.join(currentDir, "findings-group-drill-down.tsx");
  const source = readFileSync(filePath, "utf8");

  it("uses the shared finding-group resource state hook", () => {
    expect(source).toContain("useFindingGroupResourceState");
    expect(source).not.toContain("useInfiniteResources");
  });
});
