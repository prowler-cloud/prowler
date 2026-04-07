import { readFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { describe, expect, it } from "vitest";

describe("findings page", () => {
  const currentDir = path.dirname(fileURLToPath(import.meta.url));
  const pagePath = path.join(currentDir, "page.tsx");
  const source = readFileSync(pagePath, "utf8");

  it("defaults the finding groups table sort to FAIL-first when no sort is provided", () => {
    expect(source).toContain(
      'const defaultSort = "-fail_count,-severity,-last_seen_at";',
    );
  });

  it("still lets an explicit frontend sort override the default order", () => {
    expect(source).toContain("sort: searchParams.sort ?? defaultSort");
  });
});
