import { readFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { describe, expect, it } from "vitest";

describe("scan config page", () => {
  it("does not block SSR on the full providers crawl", () => {
    // Given
    const currentDir = path.dirname(fileURLToPath(import.meta.url));
    const source = readFileSync(path.join(currentDir, "page.tsx"), "utf8");

    // Then
    expect(source).not.toContain("getAllProviders");
    expect(source).toContain("getProviders({ pageSize: 100 })");
    expect(source).toContain("throw new Error");
  });
});
