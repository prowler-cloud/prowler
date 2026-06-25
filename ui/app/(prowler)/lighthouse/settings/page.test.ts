import { readFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { describe, expect, it } from "vitest";

describe("Lighthouse settings page", () => {
  const currentDir = path.dirname(fileURLToPath(import.meta.url));
  const pagePath = path.join(currentDir, "page.tsx");
  const source = readFileSync(pagePath, "utf8");

  it("uses Settings as the breadcrumb title", () => {
    // Given / When / Then
    expect(source).toContain('<ContentLayout title="Settings">');
    expect(source).not.toContain("contentClassName=");
    expect(source).not.toContain("Lighthouse Configuration");
  });
});
