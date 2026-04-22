import { readFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { describe, expect, it } from "vitest";

describe("resource detail content", () => {
  const currentDir = path.dirname(fileURLToPath(import.meta.url));
  const filePath = path.join(currentDir, "resource-detail-content.tsx");
  const source = readFileSync(filePath, "utf8");

  it("renders the new finding detail drawer flow instead of the legacy finding detail component", () => {
    expect(source).toContain("FindingDetailDrawer");
    expect(source).not.toContain("FindingDetail findingDetails");
  });

  it("loads the drawer bootstrap data through a single shared resource action", () => {
    expect(source).toContain("useResourceDrawerBootstrap");
    expect(source).not.toContain("getResourceDrawerData");
    expect(source).not.toContain("listOrganizationsSafe");
    expect(source).not.toContain("getResourceById");
    expect(source).not.toContain("getLatestFindings");
  });

  it("does not import useEffect directly and relies on hooks/keyed remounts instead", () => {
    expect(source).not.toContain("useEffect");
    expect(source).not.toContain("useEffect(");
  });
});
