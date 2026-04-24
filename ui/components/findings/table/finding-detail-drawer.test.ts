import { readFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { describe, expect, it } from "vitest";

describe("finding detail drawer", () => {
  const currentDir = path.dirname(fileURLToPath(import.meta.url));
  const filePath = path.join(currentDir, "finding-detail-drawer.tsx");
  const source = readFileSync(filePath, "utf8");

  it("uses the shared resource detail drawer hook with single-resource mode", () => {
    expect(source).toContain("useResourceDetailDrawer");
    expect(source).toContain("totalResourceCount: 1");
    expect(source).toContain("initialIndex: defaultOpen || inline ? 0 : null");
  });

  it("renders the new resource detail drawer content instead of the legacy finding detail component", () => {
    expect(source).toContain("ResourceDetailDrawerContent");
    expect(source).not.toContain('from "./finding-detail"');
  });
});
