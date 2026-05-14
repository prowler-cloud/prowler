import { readFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { describe, expect, it } from "vitest";

describe("resource details sheet", () => {
  const currentDir = path.dirname(fileURLToPath(import.meta.url));
  const filePath = path.join(currentDir, "resource-details-sheet.tsx");
  const source = readFileSync(filePath, "utf8");

  it("forces a remount when switching resources so local drawer state resets without effects", () => {
    expect(source).toContain("key={resource.id}");
    expect(source).toContain("resourceDetails={resource}");
  });
});
