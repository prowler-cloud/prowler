import { readFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { describe, expect, it } from "vitest";

describe("ComplianceCard", () => {
  const currentDir = path.dirname(fileURLToPath(import.meta.url));
  const filePath = path.join(currentDir, "compliance-card.tsx");
  const source = readFileSync(filePath, "utf8");

  it("keeps the logo canvas light in dark mode", () => {
    // Given
    const darkThemeSurface = "bg-bg-neutral-tertiary";

    // When / Then
    expect(source).toContain("bg-slate-50");
    expect(source).not.toContain(darkThemeSurface);
  });
});
