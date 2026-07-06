import { readFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { describe, expect, it } from "vitest";

describe("CrossProviderHeader", () => {
  const currentDir = path.dirname(fileURLToPath(import.meta.url));
  const filePath = path.join(currentDir, "cross-provider-header.tsx");
  const source = readFileSync(filePath, "utf8");

  it("accepts a complianceId prop to build the Prowler Hub link", () => {
    expect(source).toContain("complianceId");
    expect(source).toContain("getProwlerHubComplianceUrl(complianceId)");
  });

  it("opens the Prowler Hub link in a new, safely-referrer-stripped tab", () => {
    // ``noopener`` prevents the opened tab from reaching back into this
    // window via ``window.opener``; ``noreferrer`` also strips the
    // referrer header. Both matter for any ``target="_blank"`` link to an
    // external origin.
    expect(source).toMatch(
      /target="_blank"[\s\S]{0,40}rel="noopener noreferrer"/,
    );
  });
});
