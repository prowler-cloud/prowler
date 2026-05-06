import { readFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { describe, expect, it } from "vitest";

// Structural test: the mapper file imports server-only code via the
// `<ClientAccordionContent>` chain (next-auth → next/server) so we cannot
// load the module under vitest. Mirrors the established pattern from
// `compliance-card.test.tsx` and `client-accordion-content.test.ts`.
describe("asd-essential-eight mapper", () => {
  const currentDir = path.dirname(fileURLToPath(import.meta.url));
  const filePath = path.join(currentDir, "asd-essential-eight.tsx");
  const source = readFileSync(filePath, "utf8");

  it("exports the two functions the mapper registry expects", () => {
    expect(source).toMatch(/export const mapComplianceData = /);
    expect(source).toMatch(/export const toAccordionItems = /);
  });

  it("groups requirements by Section, normalized to `1. Foo` form", () => {
    // Cosmetic normalizer mirrors the CIS mapper. Re-introducing the
    // un-normalized "1 Foo" form would silently drift the accordion
    // header style.
    expect(source).toContain('replace(/^(\\d+)\\s/, "$1. ")');
    expect(source).toContain("findOrCreateCategory");
  });

  it("uses the literal API description for both control label and requirement.description", () => {
    // Regression coverage: an earlier draft used `attrs.Description ||
    // description`, which buried the canonical ASD clause under Prowler's
    // AWS-specific commentary. The literal clause MUST surface.
    expect(source).toContain("const controlLabel = `${id} - ${description}`");
    expect(source).toMatch(/description: description,/);
    expect(source).not.toMatch(/description: attrs\.Description \|\|/);
  });

  it("exposes the AWS-specific note as a separate `aws_description` field", () => {
    // The Attributes[].Description field carries Prowler's AWS commentary;
    // it must be preserved on the requirement so the details panel can
    // render it under "AWS Implementation Notes".
    expect(source).toContain("aws_description: attrs.Description");
  });

  it("propagates every metadata field onto the requirement", () => {
    // Spot-check that no field silently disappeared during a refactor.
    const propagated = [
      "maturity_level: attrs.MaturityLevel",
      "assessment_status: attrs.AssessmentStatus",
      "cloud_applicability: attrs.CloudApplicability",
      "mitigated_threats: attrs.MitigatedThreats || []",
      "rationale_statement: attrs.RationaleStatement",
      "impact_statement: attrs.ImpactStatement",
      "remediation_procedure: attrs.RemediationProcedure",
      "audit_procedure: attrs.AuditProcedure",
      "additional_information: attrs.AdditionalInformation",
      "references: attrs.References",
    ];
    for (const expected of propagated) {
      expect(source, `expected the mapper to set "${expected}"`).toContain(
        expected,
      );
    }
  });

  it("defends Section against null/undefined with the Uncategorized fallback", () => {
    expect(source).toContain('attrs.Section ?? "Uncategorized"');
  });

  it("accepts a `_filter` parameter even though it is currently unused (placeholder for ML2/ML3)", () => {
    expect(source).toMatch(/_filter\?:\s*string/);
  });

  it("derives status counters from RequirementStatus, not from metadata flags", () => {
    // Ensures the counters track the runtime status (PASS/FAIL/MANUAL)
    // rather than the metadata's static AssessmentStatus.
    expect(source).toContain("REQUIREMENT_STATUS.PASS ? 1 : 0");
    expect(source).toContain("REQUIREMENT_STATUS.FAIL ? 1 : 0");
    expect(source).toContain("REQUIREMENT_STATUS.MANUAL ? 1 : 0");
  });
});
