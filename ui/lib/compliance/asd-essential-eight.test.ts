import { isValidElement } from "react";
import { describe, expect, it, vi } from "vitest";

// `asd-essential-eight.tsx` re-exports `toAccordionItems` which builds JSX
// referencing client-side accordion components. Those components transitively
// import server-only code (next-auth → next/server) and would crash vitest
// at load time. Mocking the JSX deps lets us load the module and exercise
// the real `mapComplianceData` and `toAccordionItems` functions, which are
// what we actually want to test.
vi.mock(
  "@/components/compliance/compliance-accordion/client-accordion-content",
  () => ({
    ClientAccordionContent: () => null,
  }),
);
vi.mock(
  "@/components/compliance/compliance-accordion/compliance-accordion-requeriment-title",
  () => ({
    ComplianceAccordionRequirementTitle: () => null,
  }),
);
vi.mock(
  "@/components/compliance/compliance-accordion/compliance-accordion-title",
  () => ({
    ComplianceAccordionTitle: () => null,
  }),
);

import {
  ASDEssentialEightAttributesMetadata,
  AttributesData,
  AttributesItemData,
  REQUIREMENT_STATUS,
  RequirementItemData,
  RequirementsData,
  RequirementStatus,
} from "@/types/compliance";

import { mapComplianceData, toAccordionItems } from "./asd-essential-eight";

const FRAMEWORK = "ASD-Essential-Eight";

const baseMetadata = (
  overrides: Partial<ASDEssentialEightAttributesMetadata> = {},
): ASDEssentialEightAttributesMetadata => ({
  Section: "1 Patch applications",
  MaturityLevel: "ML1",
  AssessmentStatus: "Automated",
  CloudApplicability: "full",
  MitigatedThreats: ["T1190"],
  Description: "Provider-specific implementation note.",
  RationaleStatement: "Why this matters.",
  ImpactStatement: "Impact when not in place.",
  RemediationProcedure: "Steps to remediate.",
  AuditProcedure: "Steps to audit.",
  AdditionalInformation: "Extra context.",
  References: "https://example.com/a, https://example.com/b",
  ...overrides,
});

const buildAttribute = (
  id: string,
  description: string,
  metadata: ASDEssentialEightAttributesMetadata,
  checks: string[] = ["check_one"],
): AttributesItemData => ({
  type: "compliance-requirements-attributes",
  id,
  attributes: {
    framework_description: "ASD Essential Eight",
    framework: FRAMEWORK,
    version: "1.0",
    description,
    attributes: {
      metadata: [metadata],
      check_ids: checks,
    },
  },
});

const buildRequirement = (
  id: string,
  status: RequirementStatus = REQUIREMENT_STATUS.PASS,
): RequirementItemData => ({
  type: "compliance-requirements-details",
  id,
  attributes: {
    framework: FRAMEWORK,
    version: "1.0",
    description: "Canonical ASD clause text.",
    status,
  },
});

const buildInputs = (
  pairs: Array<{
    attribute: AttributesItemData;
    requirement: RequirementItemData;
  }>,
): { attributesData: AttributesData; requirementsData: RequirementsData } => ({
  attributesData: { data: pairs.map((p) => p.attribute) },
  requirementsData: { data: pairs.map((p) => p.requirement) },
});

describe("mapComplianceData (ASD Essential Eight)", () => {
  it("returns an empty list when there are no attributes", () => {
    const { attributesData, requirementsData } = buildInputs([]);
    expect(mapComplianceData(attributesData, requirementsData)).toEqual([]);
  });

  it("creates one framework with one category containing one control per requirement", () => {
    const attribute = buildAttribute(
      "E8-PA-1",
      "Apply patches to applications.",
      baseMetadata(),
    );
    const requirement = buildRequirement("E8-PA-1");
    const { attributesData, requirementsData } = buildInputs([
      { attribute, requirement },
    ]);

    const [framework] = mapComplianceData(attributesData, requirementsData);

    expect(framework.name).toBe(FRAMEWORK);
    expect(framework.categories).toHaveLength(1);
    expect(framework.categories[0].controls).toHaveLength(1);
    expect(framework.categories[0].controls[0].requirements).toHaveLength(1);
  });

  it("normalizes 'N Foo' Section names to 'N. Foo' for the accordion header", () => {
    const attribute = buildAttribute(
      "E8-PA-1",
      "Apply patches.",
      baseMetadata({ Section: "1 Patch applications" }),
    );
    const requirement = buildRequirement("E8-PA-1");
    const { attributesData, requirementsData } = buildInputs([
      { attribute, requirement },
    ]);

    const [framework] = mapComplianceData(attributesData, requirementsData);
    expect(framework.categories[0].name).toBe("1. Patch applications");
  });

  it("uses the literal API description (not the metadata Description) for the requirement description", () => {
    // Regression: an earlier draft surfaced `attrs.Description` (provider
    // commentary) in place of the canonical clause. The literal API
    // description must win.
    const attribute = buildAttribute(
      "E8-PA-1",
      "Canonical clause text.",
      baseMetadata({ Description: "Provider-specific commentary." }),
    );
    const requirement = buildRequirement("E8-PA-1");
    const { attributesData, requirementsData } = buildInputs([
      { attribute, requirement },
    ]);

    const [framework] = mapComplianceData(attributesData, requirementsData);
    const requirementOut = framework.categories[0].controls[0].requirements[0];

    expect(requirementOut.description).toBe("Canonical clause text.");
    expect(framework.categories[0].controls[0].label).toBe(
      "E8-PA-1 - Canonical clause text.",
    );
  });

  it("exposes provider commentary as `implementation_notes` (not `aws_description`)", () => {
    const attribute = buildAttribute(
      "E8-PA-1",
      "Canonical clause text.",
      baseMetadata({ Description: "Provider commentary." }),
    );
    const requirement = buildRequirement("E8-PA-1");
    const { attributesData, requirementsData } = buildInputs([
      { attribute, requirement },
    ]);

    const [framework] = mapComplianceData(attributesData, requirementsData);
    const requirementOut = framework.categories[0].controls[0].requirements[0];

    expect(requirementOut.implementation_notes).toBe("Provider commentary.");
    // The legacy field name must NOT be set, so a stale UI reading
    // `aws_description` surfaces the regression instead of silently
    // falling back to undefined.
    expect(requirementOut.aws_description).toBeUndefined();
  });

  it("propagates every metadata field onto the requirement", () => {
    const metadata = baseMetadata({
      Section: "2 Patch operating systems",
      MaturityLevel: "ML1",
      AssessmentStatus: "Manual",
      CloudApplicability: "partial",
      MitigatedThreats: ["T1059", "T1190"],
      RationaleStatement: "Rationale.",
      ImpactStatement: "Impact.",
      RemediationProcedure: "Remediate.",
      AuditProcedure: "Audit.",
      AdditionalInformation: "More info.",
      References: "https://example.com/x",
    });
    const attribute = buildAttribute("E8-OS-1", "OS patching.", metadata);
    const requirement = buildRequirement("E8-OS-1");
    const { attributesData, requirementsData } = buildInputs([
      { attribute, requirement },
    ]);

    const [framework] = mapComplianceData(attributesData, requirementsData);
    const requirementOut = framework.categories[0].controls[0].requirements[0];

    expect(requirementOut.maturity_level).toBe("ML1");
    expect(requirementOut.assessment_status).toBe("Manual");
    expect(requirementOut.cloud_applicability).toBe("partial");
    expect(requirementOut.mitigated_threats).toEqual(["T1059", "T1190"]);
    expect(requirementOut.rationale_statement).toBe("Rationale.");
    expect(requirementOut.impact_statement).toBe("Impact.");
    expect(requirementOut.remediation_procedure).toBe("Remediate.");
    expect(requirementOut.audit_procedure).toBe("Audit.");
    expect(requirementOut.additional_information).toBe("More info.");
    expect(requirementOut.references).toBe("https://example.com/x");
  });

  it("derives counters from RequirementStatus, not from metadata flags", () => {
    const cases: Array<{
      status: RequirementStatus;
      expected: "pass" | "fail" | "manual";
    }> = [
      { status: REQUIREMENT_STATUS.PASS, expected: "pass" },
      { status: REQUIREMENT_STATUS.FAIL, expected: "fail" },
      { status: REQUIREMENT_STATUS.MANUAL, expected: "manual" },
    ];

    for (const { status, expected } of cases) {
      const attribute = buildAttribute(
        `E8-${status}`,
        "clause",
        baseMetadata(),
      );
      const requirement = buildRequirement(`E8-${status}`, status);
      const { attributesData, requirementsData } = buildInputs([
        { attribute, requirement },
      ]);

      const [framework] = mapComplianceData(attributesData, requirementsData);
      const requirementOut =
        framework.categories[0].controls[0].requirements[0];

      expect(requirementOut.pass).toBe(expected === "pass" ? 1 : 0);
      expect(requirementOut.fail).toBe(expected === "fail" ? 1 : 0);
      expect(requirementOut.manual).toBe(expected === "manual" ? 1 : 0);
    }
  });

  it("groups requirements with the same Section under one category", () => {
    const attrA = buildAttribute(
      "E8-PA-1",
      "App patching A.",
      baseMetadata({ Section: "1 Patch applications" }),
    );
    const attrB = buildAttribute(
      "E8-PA-2",
      "App patching B.",
      baseMetadata({ Section: "1 Patch applications" }),
    );
    const attrC = buildAttribute(
      "E8-OS-1",
      "OS patching.",
      baseMetadata({ Section: "2 Patch operating systems" }),
    );

    const { attributesData, requirementsData } = buildInputs([
      { attribute: attrA, requirement: buildRequirement("E8-PA-1") },
      { attribute: attrB, requirement: buildRequirement("E8-PA-2") },
      { attribute: attrC, requirement: buildRequirement("E8-OS-1") },
    ]);

    const [framework] = mapComplianceData(attributesData, requirementsData);

    expect(framework.categories.map((c) => c.name)).toEqual([
      "1. Patch applications",
      "2. Patch operating systems",
    ]);
    expect(framework.categories[0].controls).toHaveLength(2);
    expect(framework.categories[1].controls).toHaveLength(1);
  });

  it("skips attribute items whose metadata is missing", () => {
    const valid = buildAttribute("E8-PA-1", "valid", baseMetadata());
    const broken: AttributesItemData = {
      ...buildAttribute("E8-PA-2", "broken", baseMetadata()),
      attributes: {
        ...buildAttribute("E8-PA-2", "broken", baseMetadata()).attributes,
        attributes: {
          metadata: [],
          check_ids: [],
        },
      },
    };

    const { attributesData, requirementsData } = buildInputs([
      { attribute: valid, requirement: buildRequirement("E8-PA-1") },
      { attribute: broken, requirement: buildRequirement("E8-PA-2") },
    ]);

    const [framework] = mapComplianceData(attributesData, requirementsData);
    expect(framework.categories[0].controls).toHaveLength(1);
    expect(framework.categories[0].controls[0].requirements[0].name).toBe(
      "E8-PA-1",
    );
  });

  it("skips attribute items without a matching requirement entry", () => {
    const attribute = buildAttribute("E8-PA-1", "clause", baseMetadata());
    const orphan = buildAttribute("E8-PA-2", "orphan", baseMetadata());

    const result = mapComplianceData(
      { data: [attribute, orphan] },
      { data: [buildRequirement("E8-PA-1")] },
    );

    expect(result[0].categories[0].controls).toHaveLength(1);
  });

  it("accepts a `_filter` parameter without altering output (placeholder for ML2/ML3)", () => {
    const attribute = buildAttribute("E8-PA-1", "clause", baseMetadata());
    const { attributesData, requirementsData } = buildInputs([
      { attribute, requirement: buildRequirement("E8-PA-1") },
    ]);

    const withoutFilter = mapComplianceData(attributesData, requirementsData);
    const withFilter = mapComplianceData(
      attributesData,
      requirementsData,
      "ML2",
    );

    expect(withFilter).toEqual(withoutFilter);
  });
});

describe("toAccordionItems (ASD Essential Eight)", () => {
  it("produces one accordion item per category", () => {
    const attrA = buildAttribute(
      "E8-PA-1",
      "App patching.",
      baseMetadata({ Section: "1 Patch applications" }),
    );
    const attrB = buildAttribute(
      "E8-OS-1",
      "OS patching.",
      baseMetadata({ Section: "2 Patch operating systems" }),
    );

    const frameworks = mapComplianceData(
      { data: [attrA, attrB] },
      {
        data: [buildRequirement("E8-PA-1"), buildRequirement("E8-OS-1")],
      },
    );

    const items = toAccordionItems(frameworks, "scan-1");

    expect(items).toHaveLength(2);
    expect(items[0].key).toBe(`${FRAMEWORK}-1. Patch applications`);
    expect(items[1].key).toBe(`${FRAMEWORK}-2. Patch operating systems`);
    // Every accordion item exposes a renderable React element title and
    // children — both of which we assert structurally (we mocked the
    // underlying components, but the elements themselves must exist).
    expect(isValidElement(items[0].title)).toBe(true);
    expect(items[0].items).toHaveLength(1);
  });

  it("returns an empty list when given no frameworks", () => {
    expect(toAccordionItems([], "scan-1")).toEqual([]);
  });
});
