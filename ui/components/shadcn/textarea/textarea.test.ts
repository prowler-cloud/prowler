import { readFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { describe, expect, it } from "vitest";

describe("Textarea", () => {
  it("does not import Next font loaders from the shared primitive", () => {
    // Given
    const currentDir = path.dirname(fileURLToPath(import.meta.url));
    const source = readFileSync(path.join(currentDir, "textarea.tsx"), "utf8");

    // Then
    expect(source).not.toContain("@/config/fonts");
    expect(source).not.toContain("next/font");
  });
});
