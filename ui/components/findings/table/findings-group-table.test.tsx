import { readFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { describe, expect, it } from "vitest";

describe("findings group table", () => {
  const currentDir = path.dirname(fileURLToPath(import.meta.url));
  const filePath = path.join(currentDir, "findings-group-table.tsx");
  const source = readFileSync(filePath, "utf8");

  it("refreshes grouped findings locally after mute instead of forcing a router refresh", () => {
    expect(source).toContain("refreshFindingGroups");
    expect(source).toContain("adaptFindingGroupsResponse");
    expect(source).toContain("getLatestFindingGroups");
    expect(source).not.toContain("router.refresh()");
  });
});
