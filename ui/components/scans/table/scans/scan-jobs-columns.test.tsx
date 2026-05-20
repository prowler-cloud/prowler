import { readFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { describe, expect, it } from "vitest";

const currentDir = path.dirname(fileURLToPath(import.meta.url));
const filePath = path.join(currentDir, "scan-jobs-columns.tsx");
const source = readFileSync(filePath, "utf8");

const getColumnsSource = (name: string): string => {
  const start = source.indexOf(`const ${name} =`);
  const end = source.indexOf("];", start);

  return source.slice(start, end);
};

describe("getScanJobsColumns", () => {
  it("does not show resources for active scans because they are still running", () => {
    expect(getColumnsSource("activeColumns")).not.toContain("resourcesColumn");
  });

  it("keeps resources visible for completed scans", () => {
    expect(getColumnsSource("completedColumns")).toContain("resourcesColumn");
  });

  it("uses Badge variants for scan status colors instead of inline status color classes", () => {
    expect(source).toContain('variant="warning"');
    expect(source).toContain('variant="success"');
    expect(source).toContain('variant="error"');
    expect(source).not.toContain("variantClassName");
  });
});
