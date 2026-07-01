import { readFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { describe, expect, it } from "vitest";

describe("inline resource container", () => {
  const currentDir = path.dirname(fileURLToPath(import.meta.url));
  const filePath = path.join(currentDir, "inline-resource-container.tsx");
  const source = readFileSync(filePath, "utf8");

  it("uses the shared finding-group resource state hook", () => {
    expect(source).toContain("useFindingGroupResourceState");
    expect(source).not.toContain("useInfiniteResources");
  });

  it("keeps horizontal overflow inside the expanded finding group", () => {
    expect(source).toContain('className="max-w-0 p-0"');
    expect(source).toContain("overflow-auto");
    expect(source).toContain("w-max min-w-full");
  });

  it("keeps the expanded resource actions column sticky inside its horizontal scroll", () => {
    expect(source).toContain('const ACTIONS_COLUMN_ID = "actions"');
    expect(source).toContain("STICKY_RESOURCE_ACTION_CELL_CLASS");
    expect(source).toContain("sticky right-0 z-20 min-w-12");
    expect(source).toContain('className="group cursor-pointer"');
    expect(source).toMatch(
      /getResourceCellClassName\(\s*cell\.column\.id,\s*\)/,
    );
  });

  it("top-aligns compact labeled resource cells so their labels line up", () => {
    expect(source).toContain("COMPACT_LABELED_COLUMN_IDS");
    expect(source).toContain('"service"');
    expect(source).toContain('"region"');
    expect(source).toContain('"lastSeen"');
    expect(source).toContain('"failingFor"');
    expect(source).toContain('"triage"');
    expect(source).toContain("align-top");
  });

  it("keeps the loading skeleton actions cell as the last visible resource column", () => {
    const triageCommentIndex = source.indexOf("{/* Triage */}");
    const actionsCommentIndex = source.indexOf("{/* Actions */}");

    expect(triageCommentIndex).toBeGreaterThan(-1);
    expect(actionsCommentIndex).toBeGreaterThan(triageCommentIndex);
    expect(source).not.toContain("{/* Notes */}");
  });
});
