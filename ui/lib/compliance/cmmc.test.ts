import { isValidElement } from "react";
import { describe, expect, it, vi } from "vitest";

// `cmmc.tsx` re-exports `toAccordionItems` which builds JSX referencing
// client-side accordion components. Those components transitively import
// server-only code (next-auth → next/server) and would crash vitest at load
// time. Mocking the JSX deps lets us load the module and exercise the real
// `mapComplianceData` and `toAccordionItems` functions.
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
  AttributesData,
  AttributesItemData,
  CMMCAttributesMetadata,
  CMMCLevel,
  REQUIREMENT_STATUS,
  RequirementItemData,
  RequirementsData,
  RequirementStatus,
} from "@/types/compliance";

import { mapComplianceData, toAccordionItems } from "./cmmc";

const FRAMEWORK = "CMMC";

const baseMetadata = (
  overrides: Partial<CMMCAttributesMetadata> = {},
): CMMCAttributesMetadata => ({
  Domain: "Access Control",
  Level: "Level 1" as CMMCLevel,
  SourceRequirement: "48 CFR 52.204-21(b)(1)(i)",
  ...overrides,
});

const buildAttribute = (
  id: string,
  metadata: CMMCAttributesMetadata,
  { name = "" }: { name?: string } = {},
): AttributesItemData => ({
  type: "compliance-requirements-attributes",
  id,
  attributes: {
    framework_description: "CMMC 2.0",
    name,
    framework: FRAMEWORK,
    version: "2.0",
    description: "Requirement clause text.",
    attributes: {
      metadata: [metadata],
      check_ids: ["check_one"],
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
    version: "2.0",
    description: "Canonical CMMC requirement text.",
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

describe("mapComplianceData (CMMC 2.0)", () => {
  it("returns an empty list when there are no attributes", () => {
    const { attributesData, requirementsData } = buildInputs([]);
    expect(mapComplianceData(attributesData, requirementsData)).toEqual([]);
  });

  it("groups requirements by Domain", () => {
    const attrA = buildAttribute(
      "AC.L1-b.1.i",
      baseMetadata({ Domain: "Access Control" }),
    );
    const attrB = buildAttribute(
      "AC.L2-3.1.3",
      baseMetadata({ Domain: "Access Control" }),
    );

    const { attributesData, requirementsData } = buildInputs([
      { attribute: attrA, requirement: buildRequirement("AC.L1-b.1.i") },
      { attribute: attrB, requirement: buildRequirement("AC.L2-3.1.3") },
    ]);

    const [framework] = mapComplianceData(attributesData, requirementsData);

    expect(framework.name).toBe(FRAMEWORK);
    expect(framework.categories).toHaveLength(1);
    expect(framework.categories[0].name).toBe("Access Control");
    expect(framework.categories[0].controls[0].requirements).toHaveLength(2);
  });

  it("orders domains by the canonical NIST 800-171 family order", () => {
    const attrSI = buildAttribute(
      "SI.L1-b.1.xiv",
      baseMetadata({ Domain: "System and Information Integrity" }),
    );
    const attrAC = buildAttribute(
      "AC.L1-b.1.i",
      baseMetadata({ Domain: "Access Control" }),
    );

    const { attributesData, requirementsData } = buildInputs([
      { attribute: attrSI, requirement: buildRequirement("SI.L1-b.1.xiv") },
      { attribute: attrAC, requirement: buildRequirement("AC.L1-b.1.i") },
    ]);

    const [framework] = mapComplianceData(attributesData, requirementsData);

    expect(framework.categories.map((c) => c.name)).toEqual([
      "Access Control",
      "System and Information Integrity",
    ]);
  });

  it("propagates Domain, Level and SourceRequirement onto the requirement", () => {
    const attribute = buildAttribute(
      "AC.L1-b.1.i",
      baseMetadata({
        Domain: "Access Control",
        Level: "Level 1" as CMMCLevel,
        SourceRequirement: "48 CFR 52.204-21(b)(1)(i)",
      }),
      { name: "Limit information system access" },
    );

    const { attributesData, requirementsData } = buildInputs([
      { attribute, requirement: buildRequirement("AC.L1-b.1.i") },
    ]);

    const [framework] = mapComplianceData(attributesData, requirementsData);
    const requirementOut = framework.categories[0].controls[0].requirements[0];

    expect(requirementOut.name).toBe(
      "AC.L1-b.1.i - Limit information system access",
    );
    expect(requirementOut.domain).toBe("Access Control");
    expect(requirementOut.level).toBe("Level 1");
    expect(requirementOut.source_requirement).toBe("48 CFR 52.204-21(b)(1)(i)");
  });

  it("derives counters from RequirementStatus", () => {
    const STATUS_COUNTER = {
      PASS: "pass",
      FAIL: "fail",
      MANUAL: "manual",
    } as const;
    type StatusCounter = (typeof STATUS_COUNTER)[keyof typeof STATUS_COUNTER];

    const cases: Array<{
      status: RequirementStatus;
      expected: StatusCounter;
    }> = [
      { status: REQUIREMENT_STATUS.PASS, expected: STATUS_COUNTER.PASS },
      { status: REQUIREMENT_STATUS.FAIL, expected: STATUS_COUNTER.FAIL },
      { status: REQUIREMENT_STATUS.MANUAL, expected: STATUS_COUNTER.MANUAL },
    ];

    for (const { status, expected } of cases) {
      const attribute = buildAttribute(`AC-${status}`, baseMetadata());
      const { attributesData, requirementsData } = buildInputs([
        { attribute, requirement: buildRequirement(`AC-${status}`, status) },
      ]);

      const [framework] = mapComplianceData(attributesData, requirementsData);
      expect(framework[expected]).toBe(1);
    }
  });
});

describe("toAccordionItems (CMMC 2.0)", () => {
  it("produces one accordion item per domain with its requirement leaves", () => {
    const attrAC = buildAttribute(
      "AC.L1-b.1.i",
      baseMetadata({ Domain: "Access Control" }),
    );
    const attrIA = buildAttribute(
      "IA.L1-b.1.v",
      baseMetadata({ Domain: "Identification and Authentication" }),
    );

    const frameworks = mapComplianceData(
      { data: [attrAC, attrIA] },
      {
        data: [
          buildRequirement("AC.L1-b.1.i"),
          buildRequirement("IA.L1-b.1.v"),
        ],
      },
    );

    const items = toAccordionItems(frameworks, "scan-1");

    expect(items).toHaveLength(2);
    expect(items[0].key).toBe(`${FRAMEWORK}-Access Control`);
    expect(isValidElement(items[0].title)).toBe(true);
    expect(items[0].items).toHaveLength(1);
    // Requirement keys are stable (derived from the requirement id), not
    // positional indexes — reordering must not remap expanded state.
    expect(items[0].items?.[0]?.key).toBe(
      `${FRAMEWORK}-Access Control-AC.L1-b.1.i`,
    );
  });

  it("returns an empty list when given no frameworks", () => {
    expect(toAccordionItems([], "scan-1")).toEqual([]);
  });
});
