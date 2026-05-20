import { readFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { describe, expect, it } from "vitest";

describe("ScansPageShell spacing", () => {
  const currentDir = path.dirname(fileURLToPath(import.meta.url));
  const filePath = path.join(currentDir, "scans-page-shell.tsx");
  const source = readFileSync(filePath, "utf8");

  it("keeps 18px spacing from filters to tabs and from tabs to table", () => {
    expect(source).toContain('className="flex flex-col gap-[18px]"');
    expect(source).toContain('className="mt-0"');
    expect(source).not.toContain("gap-5");
  });
});
