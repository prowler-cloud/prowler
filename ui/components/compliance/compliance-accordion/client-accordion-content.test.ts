import { readFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { describe, expect, it } from "vitest";

describe("client accordion content", () => {
  const currentDir = path.dirname(fileURLToPath(import.meta.url));
  const filePath = path.join(currentDir, "client-accordion-content.tsx");
  const source = readFileSync(filePath, "utf8");

  it("uses the shared standalone finding columns instead of the legacy findings columns", () => {
    expect(source).toContain("getStandaloneFindingColumns");
    expect(source).not.toContain("getColumnFindings");
  });

  it("wires triage update and note loading actions into compliance findings", () => {
    expect(source).toContain("updateFindingTriage");
    expect(source).toContain("loadLatestFindingTriageNote");
    expect(source).toContain("onTriageUpdateAction");
    expect(source).toContain("onTriageNoteLoadAction");
  });

  it("refetches findings after mutelist-shortcut triage updates like the resource drawer", () => {
    expect(source).toContain("shouldRefreshAfterTriageUpdate");
    expect(source).toContain("reload()");
  });

  it("delegates data fetching to the hook instead of effect/ref choreography", () => {
    expect(source).toContain("useRequirementFindings");
    expect(source).not.toContain("useEffect");
    expect(source).not.toContain("useRef");
  });

  it("gates the skeleton on the hook loading state and surfaces fetch errors", () => {
    // A disabled fetch (e.g. "No findings" status) must not skeleton forever,
    // and a failed fetch must offer a retry instead of hanging.
    expect(source).toContain("isLoading && requirement.status");
    expect(source).not.toContain("findings === null");
    expect(source).toContain("Try again");
  });
});
