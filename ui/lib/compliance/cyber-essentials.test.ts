import { describe, expect, it, vi } from "vitest";

// `cyber-essentials.tsx` re-exports `toAccordionItems`, which builds JSX
// referencing the client-side accordion components. Those components
// transitively import server-only code (next-auth → next/server) and would
// crash vitest at load time. Mocking the JSX deps lets us load the module and
// exercise the real `mapComplianceData` and `toAccordionItems` functions,
// which are what we actually want to test.
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
  CyberEssentialsAttributesMetadata,
  CyberEssentialsTheme,
  REQUIREMENT_STATUS,
  RequirementItemData,
  RequirementsData,
  RequirementStatus,
} from "@/types/compliance";

import {
  CYBER_ESSENTIALS_THEME_ORDER,
  mapComplianceData,
  toAccordionItems,
} from "./cyber-essentials";

const FRAMEWORK = "Cyber-Essentials";

const baseMetadata = (
  overrides: Partial<CyberEssentialsAttributesMetadata> = {},
): CyberEssentialsAttributesMetadata => ({
  Theme: "Firewalls",
  AssessmentStatus: "Automated",
  CloudApplicability: "full",
  RemediationProcedure: "Steps to remediate.",
  References: "https://example.com/a",
  ...overrides,
});

const buildAttribute = (
  id: string,
  metadata: CyberEssentialsAttributesMetadata,
  {
    name,
    description = "Canonical Cyber Essentials clause text.",
    checks = ["check_one"],
  }: { name?: string; description?: string; checks?: string[] } = {},
): AttributesItemData => ({
  type: "compliance-requirements-attributes",
  id,
  attributes: {
    framework_description: "NCSC Cyber Essentials",
    framework: FRAMEWORK,
    ...(name !== undefined ? { name } : {}),
    version: "3.3",
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
    version: "3.3",
    description: "Canonical clause text.",
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

// One requirement per theme, intentionally supplied OUT of canonical order so
// the sort under test has something to reorder.
const oneRequirementPerThemeUnordered = (): Array<{
  attribute: AttributesItemData;
  requirement: RequirementItemData;
}> => {
  const themesOutOfOrder: CyberEssentialsTheme[] = [
    "Malware Protection",
    "User Access Control",
    "Firewalls",
    "Security Update Management",
    "Secure Configuration",
  ];
  return themesOutOfOrder.map((theme, index) => {
    const id = `CE-${index}`;
    return {
      attribute: buildAttribute(id, baseMetadata({ Theme: theme })),
      requirement: buildRequirement(id),
    };
  });
};

describe("mapComplianceData (Cyber Essentials)", () => {
  it("returns an empty list when there are no attributes", () => {
    const { attributesData, requirementsData } = buildInputs([]);
    expect(mapComplianceData(attributesData, requirementsData)).toEqual([]);
  });

  describe("five-theme grouping and order", () => {
    it("orders the five themes into the canonical reading order regardless of API order", () => {
      const { attributesData, requirementsData } = buildInputs(
        oneRequirementPerThemeUnordered(),
      );

      const [framework] = mapComplianceData(attributesData, requirementsData);

      expect(framework.categories.map((c) => c.name)).toEqual([
        ...CYBER_ESSENTIALS_THEME_ORDER,
      ]);
    });

    it("groups every requirement sharing a Theme under a single category", () => {
      const pairs = [
        {
          attribute: buildAttribute(
            "CE-FW-1",
            baseMetadata({ Theme: "Firewalls" }),
          ),
          requirement: buildRequirement("CE-FW-1"),
        },
        {
          attribute: buildAttribute(
            "CE-FW-2",
            baseMetadata({ Theme: "Firewalls" }),
          ),
          requirement: buildRequirement("CE-FW-2"),
        },
        {
          attribute: buildAttribute(
            "CE-MP-1",
            baseMetadata({ Theme: "Malware Protection" }),
          ),
          requirement: buildRequirement("CE-MP-1"),
        },
      ];
      const { attributesData, requirementsData } = buildInputs(pairs);

      const [framework] = mapComplianceData(attributesData, requirementsData);

      const firewalls = framework.categories.find(
        (c) => c.name === "Firewalls",
      );
      const malware = framework.categories.find(
        (c) => c.name === "Malware Protection",
      );

      expect(framework.categories).toHaveLength(2);
      // Flat 2-level structure: theme → single control → requirements.
      expect(firewalls?.controls).toHaveLength(1);
      expect(firewalls?.controls[0].requirements).toHaveLength(2);
      expect(malware?.controls[0].requirements).toHaveLength(1);
    });

    it("sinks an unknown theme below the five canonical themes", () => {
      const pairs = [
        {
          attribute: buildAttribute("CE-X-1", {
            ...baseMetadata(),
            Theme: "Some Future Theme" as CyberEssentialsTheme,
          }),
          requirement: buildRequirement("CE-X-1"),
        },
        {
          attribute: buildAttribute(
            "CE-MP-1",
            baseMetadata({ Theme: "Malware Protection" }),
          ),
          requirement: buildRequirement("CE-MP-1"),
        },
      ];
      const { attributesData, requirementsData } = buildInputs(pairs);

      const [framework] = mapComplianceData(attributesData, requirementsData);

      expect(framework.categories.map((c) => c.name)).toEqual([
        "Malware Protection",
        "Some Future Theme",
      ]);
    });
  });

  describe("status counters", () => {
    it("derives per-requirement counters from RequirementStatus", () => {
      const cases: Array<{
        status: RequirementStatus;
        expected: "pass" | "fail" | "manual";
      }> = [
        { status: REQUIREMENT_STATUS.PASS, expected: "pass" },
        { status: REQUIREMENT_STATUS.FAIL, expected: "fail" },
        { status: REQUIREMENT_STATUS.MANUAL, expected: "manual" },
      ];

      for (const { status, expected } of cases) {
        const { attributesData, requirementsData } = buildInputs([
          {
            attribute: buildAttribute(`CE-${status}`, baseMetadata()),
            requirement: buildRequirement(`CE-${status}`, status),
          },
        ]);

        const [framework] = mapComplianceData(attributesData, requirementsData);
        const requirementOut =
          framework.categories[0].controls[0].requirements[0];

        expect(requirementOut.pass).toBe(expected === "pass" ? 1 : 0);
        expect(requirementOut.fail).toBe(expected === "fail" ? 1 : 0);
        expect(requirementOut.manual).toBe(expected === "manual" ? 1 : 0);
      }
    });

    it("aggregates counters up through category and framework levels", () => {
      const pairs = [
        {
          attribute: buildAttribute(
            "CE-FW-1",
            baseMetadata({ Theme: "Firewalls" }),
          ),
          requirement: buildRequirement("CE-FW-1", REQUIREMENT_STATUS.PASS),
        },
        {
          attribute: buildAttribute(
            "CE-FW-2",
            baseMetadata({ Theme: "Firewalls" }),
          ),
          requirement: buildRequirement("CE-FW-2", REQUIREMENT_STATUS.FAIL),
        },
        {
          attribute: buildAttribute(
            "CE-MP-1",
            baseMetadata({ Theme: "Malware Protection" }),
          ),
          requirement: buildRequirement("CE-MP-1", REQUIREMENT_STATUS.MANUAL),
        },
      ];
      const { attributesData, requirementsData } = buildInputs(pairs);

      const [framework] = mapComplianceData(attributesData, requirementsData);

      const firewalls = framework.categories.find(
        (c) => c.name === "Firewalls",
      )!;
      expect(firewalls.pass).toBe(1);
      expect(firewalls.fail).toBe(1);
      expect(firewalls.manual).toBe(0);

      expect(framework.pass).toBe(1);
      expect(framework.fail).toBe(1);
      expect(framework.manual).toBe(1);
    });
  });

  describe("manual requirements with empty check lists", () => {
    it("carries through a MANUAL requirement that has no checks", () => {
      const { attributesData, requirementsData } = buildInputs([
        {
          attribute: buildAttribute(
            "CE-SUM-03",
            baseMetadata({
              Theme: "Security Update Management",
              AssessmentStatus: "Manual",
              CloudApplicability: "partial",
            }),
            { name: "Automatic updates enabled where possible", checks: [] },
          ),
          requirement: buildRequirement("CE-SUM-03", REQUIREMENT_STATUS.MANUAL),
        },
      ]);

      const [framework] = mapComplianceData(attributesData, requirementsData);
      const requirementOut =
        framework.categories[0].controls[0].requirements[0];

      expect(requirementOut.check_ids).toEqual([]);
      expect(requirementOut.manual).toBe(1);
      expect(requirementOut.assessment_status).toBe("Manual");
    });

    it("defaults check_ids to an empty array when the attribute omits them", () => {
      const attribute = buildAttribute("CE-SUM-01", baseMetadata());
      // Drop check_ids entirely to mimic an API payload without the field.
      delete (attribute.attributes.attributes as { check_ids?: string[] })
        .check_ids;

      const { attributesData, requirementsData } = buildInputs([
        { attribute, requirement: buildRequirement("CE-SUM-01") },
      ]);

      const [framework] = mapComplianceData(attributesData, requirementsData);
      expect(
        framework.categories[0].controls[0].requirements[0].check_ids,
      ).toEqual([]);
    });

    it("keeps findings enabled for a manual requirement with no checks", () => {
      // A MANUAL requirement carries a manual count of 1, so the accordion
      // still surfaces its (manual) finding even though it has no checks —
      // findings are only disabled when there is nothing to show at all
      // (empty checks AND no manual count).
      const { attributesData, requirementsData } = buildInputs([
        {
          attribute: buildAttribute("CE-SUM-03", baseMetadata(), {
            checks: [],
          }),
          requirement: buildRequirement("CE-SUM-03", REQUIREMENT_STATUS.MANUAL),
        },
      ]);

      const frameworks = mapComplianceData(attributesData, requirementsData);
      const items = toAccordionItems(frameworks, "scan-1");
      const content = items[0].items![0].content as {
        props: { disableFindings: boolean };
      };

      expect(content.props.disableFindings).toBe(false);
    });

    it("disables findings for a non-manual requirement that has no checks", () => {
      const { attributesData, requirementsData } = buildInputs([
        {
          attribute: buildAttribute("CE-SUM-01", baseMetadata(), {
            checks: [],
          }),
          requirement: buildRequirement("CE-SUM-01", REQUIREMENT_STATUS.PASS),
        },
      ]);

      const frameworks = mapComplianceData(attributesData, requirementsData);
      const items = toAccordionItems(frameworks, "scan-1");
      const content = items[0].items![0].content as {
        props: { disableFindings: boolean };
      };

      expect(content.props.disableFindings).toBe(true);
    });
  });

  describe("preservation of Cyber Essentials metadata fields", () => {
    it("propagates Theme, AssessmentStatus, CloudApplicability, RemediationProcedure and References", () => {
      const metadata = baseMetadata({
        Theme: "User Access Control",
        AssessmentStatus: "Manual",
        CloudApplicability: "partial",
        RemediationProcedure: "Remediate the access control gap.",
        References:
          "NCSC Cyber Essentials: Requirements for IT Infrastructure v3.3 (April 2026), Section D",
      });
      const { attributesData, requirementsData } = buildInputs([
        {
          attribute: buildAttribute("CE-UAC-1", metadata),
          requirement: buildRequirement("CE-UAC-1"),
        },
      ]);

      const [framework] = mapComplianceData(attributesData, requirementsData);
      const requirementOut =
        framework.categories[0].controls[0].requirements[0];

      expect(requirementOut.theme).toBe("User Access Control");
      expect(requirementOut.assessment_status).toBe("Manual");
      expect(requirementOut.cloud_applicability).toBe("partial");
      expect(requirementOut.remediation_procedure).toBe(
        "Remediate the access control gap.",
      );
      expect(requirementOut.references).toBe(
        "NCSC Cyber Essentials: Requirements for IT Infrastructure v3.3 (April 2026), Section D",
      );
    });

    it("prefixes the requirement name with its id when a name is present", () => {
      const { attributesData, requirementsData } = buildInputs([
        {
          attribute: buildAttribute("CE-FW-1", baseMetadata(), {
            name: "Boundary firewalls in place",
          }),
          requirement: buildRequirement("CE-FW-1"),
        },
      ]);

      const [framework] = mapComplianceData(attributesData, requirementsData);
      expect(framework.categories[0].controls[0].requirements[0].name).toBe(
        "CE-FW-1 - Boundary firewalls in place",
      );
    });

    it("falls back to the bare id when no name is supplied", () => {
      const { attributesData, requirementsData } = buildInputs([
        {
          attribute: buildAttribute("CE-FW-1", baseMetadata()),
          requirement: buildRequirement("CE-FW-1"),
        },
      ]);

      const [framework] = mapComplianceData(attributesData, requirementsData);
      expect(framework.categories[0].controls[0].requirements[0].name).toBe(
        "CE-FW-1",
      );
    });

    it("uses the literal API description for the requirement description", () => {
      const { attributesData, requirementsData } = buildInputs([
        {
          attribute: buildAttribute("CE-FW-1", baseMetadata(), {
            description: "Boundary firewalls must be configured.",
          }),
          requirement: buildRequirement("CE-FW-1"),
        },
      ]);

      const [framework] = mapComplianceData(attributesData, requirementsData);
      expect(
        framework.categories[0].controls[0].requirements[0].description,
      ).toBe("Boundary firewalls must be configured.");
    });
  });

  describe("skipping malformed entries", () => {
    it("skips attribute items whose metadata is missing", () => {
      const valid = buildAttribute("CE-FW-1", baseMetadata());
      const broken = buildAttribute("CE-FW-2", baseMetadata());
      broken.attributes.attributes.metadata = [];

      const { attributesData, requirementsData } = buildInputs([
        { attribute: valid, requirement: buildRequirement("CE-FW-1") },
        { attribute: broken, requirement: buildRequirement("CE-FW-2") },
      ]);

      const [framework] = mapComplianceData(attributesData, requirementsData);
      expect(framework.categories[0].controls[0].requirements).toHaveLength(1);
      expect(framework.categories[0].controls[0].requirements[0].name).toBe(
        "CE-FW-1",
      );
    });

    it("skips attribute items without a matching requirement entry", () => {
      const result = mapComplianceData(
        {
          data: [
            buildAttribute("CE-FW-1", baseMetadata()),
            buildAttribute("CE-FW-2", baseMetadata()),
          ],
        },
        { data: [buildRequirement("CE-FW-1")] },
      );

      expect(result[0].categories[0].controls[0].requirements).toHaveLength(1);
    });
  });
});

describe("toAccordionItems (Cyber Essentials)", () => {
  it("produces one accordion item per theme, in canonical order", () => {
    const { attributesData, requirementsData } = buildInputs(
      oneRequirementPerThemeUnordered(),
    );

    const frameworks = mapComplianceData(attributesData, requirementsData);
    const items = toAccordionItems(frameworks, "scan-1");

    expect(items.map((item) => item.key)).toEqual(
      CYBER_ESSENTIALS_THEME_ORDER.map((theme) => `${FRAMEWORK}-${theme}`),
    );
  });

  it("returns an empty list when given no frameworks", () => {
    expect(toAccordionItems([], "scan-1")).toEqual([]);
  });

  it("keeps findings enabled for an automated requirement that has checks", () => {
    const { attributesData, requirementsData } = buildInputs([
      {
        attribute: buildAttribute("CE-FW-1", baseMetadata(), {
          checks: ["check_one"],
        }),
        requirement: buildRequirement("CE-FW-1"),
      },
    ]);

    const frameworks = mapComplianceData(attributesData, requirementsData);
    const items = toAccordionItems(frameworks, "scan-1");
    const content = items[0].items![0].content as {
      props: { disableFindings: boolean };
    };

    expect(content.props.disableFindings).toBe(false);
  });
});
