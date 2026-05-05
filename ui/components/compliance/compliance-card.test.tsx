import { readFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { describe, expect, it } from "vitest";

describe("ComplianceCard", () => {
  const currentDir = path.dirname(fileURLToPath(import.meta.url));
  const filePath = path.join(currentDir, "compliance-card.tsx");
  const source = readFileSync(filePath, "utf8");

  it("keeps the shadcn Card base variant", () => {
    expect(source).toContain('variant="base"');
  });

  it("uses a responsive stacked layout for narrow screens", () => {
    expect(source).toContain("flex-col");
    expect(source).toContain("sm:flex-row");
  });

  it("uses the shadcn progress component instead of Hero UI", () => {
    expect(source).toContain('from "@/components/shadcn/progress"');
    expect(source).not.toContain("@heroui/progress");
  });

  it("places compact actions in the icon column on larger screens", () => {
    expect(source).toContain('orientation="column"');
    expect(source).toContain('buttonWidth="icon"');
  });
});
