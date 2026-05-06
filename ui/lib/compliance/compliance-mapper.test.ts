import { readFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { describe, expect, it } from "vitest";

// Structural test: `compliance-mapper.ts` re-exports framework modules that
// transitively import server-only code (next-auth → next/server) so we
// cannot load the module under vitest. Mirrors the established pattern
// from `compliance-card.test.tsx` and `client-accordion-content.test.ts`.
describe("compliance-mapper registry", () => {
  const currentDir = path.dirname(fileURLToPath(import.meta.url));
  const filePath = path.join(currentDir, "compliance-mapper.ts");
  const source = readFileSync(filePath, "utf8");

  it("registers every framework key the API can return", () => {
    // Pinning the registered keys here so a future rename or accidental
    // deletion shows up as a test failure rather than a silent fallback to
    // the generic mapper. The keys MUST match the API's `framework` field
    // exactly (case- and hyphen-sensitive).
    const expectedKeys = [
      '"ASD-Essential-Eight"',
      "C5:",
      "ENS:",
      "ISO27001:",
      "CIS:",
      '"AWS-Well-Architected-Framework-Security-Pillar"',
      '"AWS-Well-Architected-Framework-Reliability-Pillar"',
      '"KISA-ISMS-P"',
      '"MITRE-ATTACK"',
      "ProwlerThreatScore:",
      "CCC:",
      '"CSA-CCM"',
    ];
    for (const key of expectedKeys) {
      expect(source, `expected registry to contain ${key}`).toContain(key);
    }
  });

  it("wires ASD Essential Eight to its dedicated mapper functions and details component", () => {
    expect(source).toContain(
      'import { ASDEssentialEightCustomDetails } from "@/components/compliance/compliance-custom-details/asd-essential-eight-details"',
    );
    expect(source).toContain(
      "mapComplianceData as mapASDEssentialEightComplianceData",
    );
    expect(source).toContain(
      "toAccordionItems as toASDEssentialEightAccordionItems",
    );
    // The registry entry must reference the imported aliases, not the
    // generic fallback or any other framework's functions.
    expect(source).toMatch(
      /"ASD-Essential-Eight":\s*\{\s*mapComplianceData:\s*mapASDEssentialEightComplianceData,\s*toAccordionItems:\s*toASDEssentialEightAccordionItems/,
    );
    expect(source).toContain(
      "createElement(ASDEssentialEightCustomDetails, { requirement })",
    );
  });

  it("falls back to the generic mapper when the framework is unknown", () => {
    expect(source).toContain(
      "complianceMappers[framework] || getDefaultMapper()",
    );
    expect(source).toContain("if (!framework) {");
  });
});
