import { readFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { describe, expect, it } from "vitest";

describe("ComplianceSkeletonGrid", () => {
  const currentDir = path.dirname(fileURLToPath(import.meta.url));
  const filePath = path.join(currentDir, "compliance-grid-skeleton.tsx");
  const source = readFileSync(filePath, "utf8");

  it("uses shadcn skeletons instead of Hero UI", () => {
    expect(source).toContain('from "@/components/shadcn/skeleton/skeleton"');
    expect(source).not.toContain("@heroui/card");
    expect(source).not.toContain("@heroui/skeleton");
  });
});
