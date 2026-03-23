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

  it("does not pass non-serializable DataTable callbacks from the server page", () => {
    const currentDir = path.dirname(fileURLToPath(import.meta.url));
    const pagePath = path.join(currentDir, "page.tsx");
    const source = readFileSync(pagePath, "utf8");

    expect(source).not.toContain("getSubRows={(row) => row.subRows}");
  });

  it("keeps expandable providers columns on explicit fixed widths", () => {
    const currentDir = path.dirname(fileURLToPath(import.meta.url));
    const columnsPath = path.join(
      currentDir,
      "../../../components/providers/table/column-providers.tsx",
    );
    const source = readFileSync(columnsPath, "utf8");

    // Account is fixed, Account Groups is fluid (no explicit size)
    expect(source).toContain("size: 420");
    expect(source).toContain("size: 160");
    expect(source).toContain("size: 140");
  });
});
