import { readFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { describe, expect, it } from "vitest";

describe("findings group drill down", () => {
  const currentDir = path.dirname(fileURLToPath(import.meta.url));
  const filePath = path.join(currentDir, "findings-group-drill-down.tsx");
  const source = readFileSync(filePath, "utf8");

  it("uses the shared finding-group resource state hook", () => {
    expect(source).toContain("useFindingGroupResourceState");
    expect(source).not.toContain("useInfiniteResources");
  });

  it("routes selected child findings through the Send to Jira modal with issue creation mode", () => {
    expect(source).toContain("<SendToJiraModal");
    expect(source).toContain("JIRA_DISPATCH_TARGET.FINDING_ID");
    expect(source).toContain(
      "selectedFindingIds.length > 1 && groupedJiraDispatchEnabled",
    );
    expect(source).toContain("canSendSelectedFindingsToJira");
    expect(source).toContain("JIRA_DISPATCH_MODE.GROUPED");
  });
});
