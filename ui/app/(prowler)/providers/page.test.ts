import { readFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { describe, expect, it } from "vitest";

describe("providers page", () => {
  it("does not use unstable Date.now keys for the providers DataTable", () => {
    const currentDir = path.dirname(fileURLToPath(import.meta.url));
    const pagePath = path.join(currentDir, "page.tsx");
    const source = readFileSync(pagePath, "utf8");

    expect(source).not.toContain("key={`providers-${Date.now()}`}");
  });
});
