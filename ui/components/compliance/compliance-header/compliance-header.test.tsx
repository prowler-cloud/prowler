import { readFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { describe, expect, it } from "vitest";

describe("ComplianceHeader", () => {
  const currentDir = path.dirname(fileURLToPath(import.meta.url));
  const filePath = path.join(currentDir, "compliance-header.tsx");
  const source = readFileSync(filePath, "utf8");

  it("renders the scan selector inside the shared filters grid using default layout", () => {
    expect(source).toContain("prependElement");
    expect(source).toContain("<DataCompliance");
    expect(source).toContain("DataTableFilterCustom");
    expect(source).not.toContain("gridClassName");
  });
});
