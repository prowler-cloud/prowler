import { readFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { describe, expect, it } from "vitest";

describe("custom link", () => {
  const currentDir = path.dirname(fileURLToPath(import.meta.url));
  const filePath = path.join(currentDir, "custom-link.tsx");
  const source = readFileSync(filePath, "utf8");

  it("renders external or placeholder hrefs as plain anchors instead of next/link", () => {
    expect(source).toContain("isExternalHref");
    expect(source).toContain("hasDynamicHrefPlaceholder");
    expect(source).toContain("<a");
  });
});
