import { readFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { describe, expect, it } from "vitest";

describe("notification indicator", () => {
  const currentDir = path.dirname(fileURLToPath(import.meta.url));
  const filePath = path.join(currentDir, "notification-indicator.tsx");
  const source = readFileSync(filePath, "utf8");

  it("uses a popover for delta learn-more content so the link stays interactive", () => {
    expect(source).toContain("<Popover");
    expect(source).toContain("Learn more");
    expect(source).not.toContain("<Tooltip>");
  });
});
