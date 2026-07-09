import { describe, expect, it, vi } from "vitest";

// The mapper registry transitively imports the client accordion chain, which
// pulls server-only code (next-auth → next/server) into vitest. Stub the JSX
// leaves — mapComplianceData, the code under test here, never touches them.
// Same approach as lib/compliance/compliance-mapper.test.ts.
const { stubComponent } = vi.hoisted(() => ({
  stubComponent: () => () => null,
}));

vi.mock(
  "@/components/compliance/compliance-custom-details/asd-essential-eight-details",
  () => ({ ASDEssentialEightCustomDetails: stubComponent() }),
);
vi.mock(
  "@/components/compliance/compliance-custom-details/aws-well-architected-details",
  () => ({ AWSWellArchitectedCustomDetails: stubComponent() }),
);
vi.mock("@/components/compliance/compliance-custom-details/c5-details", () => ({
  C5CustomDetails: stubComponent(),
}));
vi.mock(
  "@/components/compliance/compliance-custom-details/ccc-details",
  () => ({ CCCCustomDetails: stubComponent() }),
);
vi.mock(
  "@/components/compliance/compliance-custom-details/cis-details",
  () => ({ CISCustomDetails: stubComponent() }),
);
vi.mock(
  "@/components/compliance/compliance-custom-details/csa-details",
  () => ({ CSACustomDetails: stubComponent() }),
);
vi.mock(
  "@/components/compliance/compliance-custom-details/ens-details",
  () => ({ ENSCustomDetails: stubComponent() }),
);
vi.mock(
  "@/components/compliance/compliance-custom-details/generic-details",
  () => ({ GenericCustomDetails: stubComponent() }),
);
vi.mock(
  "@/components/compliance/compliance-custom-details/iso-details",
  () => ({ ISOCustomDetails: stubComponent() }),
);
vi.mock(
  "@/components/compliance/compliance-custom-details/kisa-details",
  () => ({ KISACustomDetails: stubComponent() }),
);
vi.mock(
  "@/components/compliance/compliance-custom-details/mitre-details",
  () => ({ MITRECustomDetails: stubComponent() }),
);
vi.mock(
  "@/components/compliance/compliance-custom-details/threat-details",
  () => ({ ThreatCustomDetails: stubComponent() }),
);
vi.mock(
  "@/components/compliance/compliance-custom-details/okta-idaas-stig-details",
  () => ({ OktaIDaaSStigCustomDetails: stubComponent() }),
);
vi.mock(
  "@/components/compliance/compliance-custom-details/cis-controls-details",
  () => ({ CISControlsCustomDetails: stubComponent() }),
);
vi.mock(
  "@/components/compliance/compliance-custom-details/dora-details",
  () => ({ DORACustomDetails: stubComponent() }),
);

vi.mock(
  "@/components/compliance/compliance-accordion/client-accordion-content",
  () => ({ ClientAccordionContent: stubComponent() }),
);
vi.mock(
  "@/components/compliance/compliance-accordion/compliance-accordion-requeriment-title",
  () => ({ ComplianceAccordionRequirementTitle: stubComponent() }),
);
vi.mock(
  "@/components/compliance/compliance-accordion/compliance-accordion-title",
  () => ({ ComplianceAccordionTitle: stubComponent() }),
);

import { getComplianceMapper } from "@/lib/compliance/compliance-mapper";
import type { Framework, Requirement } from "@/types/compliance";

import type {
  CrossProviderOverviewAttributes,
  CrossProviderRequirementData,
} from "../../_types";
import {
  buildRequirementExtrasMap,
  computeProviderBreakdown,
  crossProviderToMapperInput,
} from "../cross-provider-adapter";

const buildAttributes = (
  overrides: Partial<CrossProviderOverviewAttributes> & {
    framework: string;
    requirements: CrossProviderRequirementData[];
  },
): CrossProviderOverviewAttributes => ({
  compliance_id: "test_1.0",
  name: "Test Framework",
  version: "1.0",
  description: "Test description",
  compatible_providers: ["aws", "azure", "gcp"],
  requested_providers: ["aws", "azure"],
  providers: ["aws", "azure"],
  scan_ids: ["scan-aws-1", "scan-azure-1"],
  scan_ids_by_provider: { aws: ["scan-aws-1"], azure: ["scan-azure-1"] },
  requirements_passed: 0,
  requirements_failed: 0,
  requirements_manual: 0,
  total_requirements: overrides.requirements.length,
  ...overrides,
});

const csaAttributes = buildAttributes({
  framework: "CSA-CCM",
  requirements: [
    {
      id: "A&A-01",
      name: "Audit and Assurance Policy and Procedures",
      description: "Establish audit policies.",
      attributes: {
        Section: "Audit & Assurance",
        CCMLite: "Yes",
        IaaS: "Yes",
        PaaS: "Yes",
        SaaS: "Yes",
        ScopeApplicability: "IaaS, PaaS, SaaS",
      },
      status: "FAIL",
      providers: { aws: "FAIL", azure: "PASS" },
      check_ids_by_provider: {
        aws: ["iam_check_1", "shared_check"],
        azure: ["entra_check_1", "shared_check"],
      },
    },
    {
      id: "A&A-02",
      name: "Independent Assessments",
      description: "Conduct independent audits.",
      attributes: {
        Section: "Audit & Assurance",
        CCMLite: "No",
        IaaS: "Yes",
        PaaS: "No",
        SaaS: "No",
        ScopeApplicability: "IaaS",
      },
      status: "MANUAL",
      providers: { aws: "MANUAL", azure: "MANUAL" },
      check_ids_by_provider: {},
    },
    {
      id: "DSP-01",
      name: "Data Security Policies",
      description: "Protect data.",
      attributes: {
        Section: "Data Security and Privacy Lifecycle Management",
        CCMLite: "Yes",
        IaaS: "Yes",
        PaaS: "Yes",
        SaaS: "Yes",
        ScopeApplicability: "IaaS",
      },
      status: "PASS",
      providers: { aws: "PASS" },
      check_ids_by_provider: { aws: ["s3_check_1"] },
    },
  ],
});

const doraAttributes = buildAttributes({
  framework: "DORA",
  requirements: [
    {
      id: "RQ-01",
      name: "ICT Risk Management",
      description: "Manage ICT risk.",
      attributes: {
        Pillar: "ICT risk management",
        Article: "Art. 5",
        ArticleTitle: "Governance and organisation",
      },
      status: "FAIL",
      providers: { aws: "FAIL", azure: "FAIL" },
      check_ids_by_provider: { aws: ["check_a"], azure: ["check_b"] },
    },
  ],
});

const cisControlsAttributes = buildAttributes({
  framework: "CIS-Controls",
  requirements: [
    {
      id: "1.1",
      name: "Establish and Maintain Detailed Enterprise Asset Inventory",
      description: "Maintain an asset inventory.",
      attributes: {
        Section: "01 Inventory and Control of Enterprise Assets",
        Function: "Identify",
        AssetType: "Devices",
        ImplementationGroups: ["IG1", "IG2", "IG3"],
      },
      status: "PASS",
      providers: { aws: "PASS" },
      check_ids_by_provider: { aws: ["ec2_check"] },
    },
  ],
});

const collectRequirements = (frameworks: Framework[]): Requirement[] =>
  frameworks.flatMap((framework) =>
    framework.categories.flatMap((category) =>
      category.controls.flatMap((control) => control.requirements),
    ),
  );

describe.each([
  ["CSA-CCM", csaAttributes],
  ["DORA", doraAttributes],
  ["CIS-Controls", cisControlsAttributes],
])("crossProviderToMapperInput through the real %s mapper", (key, attrs) => {
  const mapper = getComplianceMapper(key);
  const { attributesData, requirementsData } = crossProviderToMapperInput(
    attrs as CrossProviderOverviewAttributes,
  );
  const frameworks = mapper.mapComplianceData(attributesData, requirementsData);
  const mapped = collectRequirements(frameworks);

  it("maps every requirement exactly once", () => {
    expect(mapped).toHaveLength(
      (attrs as CrossProviderOverviewAttributes).requirements.length,
    );
  });

  it("preserves the rolled-up status of each requirement", () => {
    const statuses = Object.fromEntries(mapped.map((r) => [r.name, r.status]));
    for (const requirement of (attrs as CrossProviderOverviewAttributes)
      .requirements) {
      const composedName = `${requirement.id} - ${requirement.name}`;
      expect(statuses[composedName]).toBe(requirement.status);
    }
  });

  it("joins cross-provider extras onto every mapped requirement", () => {
    const extras = buildRequirementExtrasMap(
      attrs as CrossProviderOverviewAttributes,
    );

    for (const requirement of mapped) {
      const extra = extras.get(requirement.name as string);
      expect(extra, `no extras for "${requirement.name}"`).toBeDefined();
      expect(extra?.scanIdsByProvider).toEqual(
        (attrs as CrossProviderOverviewAttributes).scan_ids_by_provider,
      );
    }
  });

  it("gives mappers the deduped union of per-provider check ids", () => {
    for (const requirement of (attrs as CrossProviderOverviewAttributes)
      .requirements) {
      const composedName = `${requirement.id} - ${requirement.name}`;
      const mappedRequirement = mapped.find((r) => r.name === composedName);
      const expected = new Set(
        Object.values(requirement.check_ids_by_provider ?? {}).flat(),
      );
      expect(new Set(mappedRequirement?.check_ids)).toEqual(expected);
      expect(mappedRequirement?.check_ids).toHaveLength(expected.size);
    }
  });
});

describe("CSA grouping through the real mapper", () => {
  it("groups requirements by Section into categories with correct counters", () => {
    const mapper = getComplianceMapper("CSA-CCM");
    const { attributesData, requirementsData } =
      crossProviderToMapperInput(csaAttributes);
    const [framework] = mapper.mapComplianceData(
      attributesData,
      requirementsData,
    );

    expect(framework.name).toBe("CSA-CCM");
    expect(framework.categories.map((c) => c.name)).toEqual([
      "Audit & Assurance",
      "Data Security and Privacy Lifecycle Management",
    ]);
    expect(framework.pass).toBe(1);
    expect(framework.fail).toBe(1);
    expect(framework.manual).toBe(1);
  });
});

describe("computeProviderBreakdown", () => {
  it("tallies per-provider statuses and flags compatible-but-unscanned providers", () => {
    const breakdown = computeProviderBreakdown(csaAttributes);

    const aws = breakdown.find((entry) => entry.provider === "aws");
    expect(aws).toEqual({
      provider: "aws",
      pass: 1,
      fail: 1,
      manual: 1,
      total: 3,
      score: 50,
      unscanned: false,
    });

    const azure = breakdown.find((entry) => entry.provider === "azure");
    expect(azure?.pass).toBe(1);
    expect(azure?.fail).toBe(0);
    expect(azure?.manual).toBe(1);
    expect(azure?.score).toBe(100);

    const gcp = breakdown.find((entry) => entry.provider === "gcp");
    expect(gcp?.unscanned).toBe(true);
    expect(gcp?.total).toBe(0);
  });

  it("lists scanned providers first, each group alphabetically", () => {
    const breakdown = computeProviderBreakdown(
      buildAttributes({
        framework: "CSA-CCM",
        compatible_providers: ["oraclecloud", "gcp", "azure", "aws"],
        providers: ["gcp", "aws"],
        requirements: [],
      }),
    );

    expect(breakdown.map((entry) => entry.provider)).toEqual([
      "aws",
      "gcp",
      "azure",
      "oraclecloud",
    ]);
  });

  it("ignores provider types the UI does not know", () => {
    const breakdown = computeProviderBreakdown(
      buildAttributes({
        framework: "CSA-CCM",
        compatible_providers: ["aws", "not-a-provider"],
        requirements: [],
      }),
    );

    expect(breakdown.map((entry) => entry.provider)).toEqual(["aws"]);
  });
});
