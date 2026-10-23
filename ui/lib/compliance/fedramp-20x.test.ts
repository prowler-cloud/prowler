import { describe, expect, it, vi } from "vitest";

vi.mock(
  "@/components/compliance/compliance-accordion/client-accordion-content",
  () => ({ ClientAccordionContent: () => null }),
);
vi.mock(
  "@/components/compliance/compliance-accordion/compliance-accordion-requeriment-title",
  () => ({ ComplianceAccordionRequirementTitle: () => null }),
);
vi.mock(
  "@/components/compliance/compliance-accordion/compliance-accordion-title",
  () => ({ ComplianceAccordionTitle: () => null }),
);

import {
  buildRequirementExtrasMap,
  crossProviderToMapperInput,
} from "@/app/(prowler)/compliance/_lib/cross-provider-adapter";
import type { CrossProviderOverviewAttributes } from "@/app/(prowler)/compliance/_types";
import { Framework, Requirement } from "@/types/compliance";

import {
  mapFRRComplianceData,
  mapKSIComplianceData,
  toAccordionItems,
} from "./fedramp-20x";

type OverviewRequirement =
  CrossProviderOverviewAttributes["requirements"][number];

const buildOverview = (
  framework: string,
  requirements: Array<Pick<OverviewRequirement, "id" | "name" | "attributes">>,
): CrossProviderOverviewAttributes =>
  ({
    framework,
    version: "2026",
    description: "",
    providers: ["aws"],
    compatible_providers: ["aws"],
    scan_ids_by_provider: {},
    requirements: requirements.map((requirement) => ({
      ...requirement,
      description: "Requirement text.",
      status: "PASS",
      providers: { aws: "PASS" },
      check_ids_by_provider: { aws: ["check_one"] },
    })),
  }) as unknown as CrossProviderOverviewAttributes;

const mapOverview = (
  overview: CrossProviderOverviewAttributes,
  mapper: typeof mapKSIComplianceData,
): Framework[] => {
  const { attributesData, requirementsData } =
    crossProviderToMapperInput(overview);
  return mapper(attributesData, requirementsData);
};

const allRequirements = (frameworks: Framework[]): Requirement[] =>
  frameworks.flatMap((framework) =>
    framework.categories.flatMap((category) =>
      category.controls.flatMap((control) => control.requirements),
    ),
  );

const KSI_OVERVIEW = buildOverview("FedRAMP-20x-KSI", [
  {
    id: "KSI-SVC-VRI",
    name: "Validating Resource Integrity",
    attributes: {
      Theme: "KSI-SVC: Service Configuration",
      NISTControls: "SC-13",
      ClassApplicability: "Required for Classes B and C",
    },
  },
  {
    id: "KSI-CED-RAT",
    name: "Reviewing All Training",
    attributes: {
      Theme: "KSI-CED: Cybersecurity Education",
      NISTControls: null,
      ClassApplicability: "Required for Classes B and C",
    },
  },
]);

const FRR_OVERVIEW = buildOverview("FedRAMP-20x-FRR-Class-C", [
  {
    id: "CMU-CSO-UVM",
    name: "Using Validated Cryptographic Modules",
    attributes: {
      Ruleset: "CMU: Cryptographic Module Use",
      Subset: "CSO: Cloud Service Provider Responsibilities",
      Force: "MUST",
    },
  },
  {
    id: "AFC-CSO-INB",
    name: "Maintain a FedRAMP Security Inbox",
    attributes: {
      Ruleset: "AFC: Addressing FedRAMP Communication",
      Subset: "CSO: General Provider Responsibilities",
      Force: "MUST",
    },
  },
]);

describe.each([
  { label: "KSI", overview: KSI_OVERVIEW, mapper: mapKSIComplianceData },
  {
    label: "FRR Class C",
    overview: FRR_OVERVIEW,
    mapper: mapFRRComplianceData,
  },
])("FedRAMP 20x $label cross-provider join", ({ overview, mapper }) => {
  it("names every requirement with a key of the per-provider breakdown", () => {
    const extras = buildRequirementExtrasMap(overview);
    const names = allRequirements(mapOverview(overview, mapper)).map(
      (requirement) => requirement.name,
    );

    expect(names).toHaveLength(overview.requirements.length);
    for (const name of names) {
      expect(extras.has(name), name).toBe(true);
    }
  });
});

describe("mapKSIComplianceData", () => {
  it("groups by Theme in catalog order and exposes KSI attributes", () => {
    const [framework] = mapOverview(KSI_OVERVIEW, mapKSIComplianceData);

    expect(framework.categories.map((category) => category.name)).toEqual([
      "KSI-CED: Cybersecurity Education",
      "KSI-SVC: Service Configuration",
    ]);

    const [svc] = framework.categories[1].controls[0].requirements;
    expect(svc.name).toBe("KSI-SVC-VRI - Validating Resource Integrity");
    expect(svc.theme).toBe("KSI-SVC: Service Configuration");
    expect(svc.nist_controls).toBe("SC-13");
    expect(svc.class_applicability).toBe("Required for Classes B and C");

    const [ced] = framework.categories[0].controls[0].requirements;
    expect(ced.nist_controls).toBeUndefined();
  });
});

describe("mapFRRComplianceData", () => {
  it("groups by Ruleset in catalog order and exposes FRR attributes", () => {
    const [framework] = mapOverview(FRR_OVERVIEW, mapFRRComplianceData);

    expect(framework.categories.map((category) => category.name)).toEqual([
      "AFC: Addressing FedRAMP Communication",
      "CMU: Cryptographic Module Use",
    ]);

    const [cmu] = framework.categories[1].controls[0].requirements;
    expect(cmu.ruleset).toBe("CMU: Cryptographic Module Use");
    expect(cmu.subset).toBe("CSO: Cloud Service Provider Responsibilities");
    expect(cmu.force).toBe("MUST");
    expect(framework.pass).toBe(2);
  });
});

describe("toAccordionItems (FedRAMP 20x)", () => {
  it("keys requirement leaves by name instead of position", () => {
    const items = toAccordionItems(
      mapOverview(FRR_OVERVIEW, mapFRRComplianceData),
      "scan-1",
    );

    expect(items.map((item) => item.key)).toEqual([
      "FedRAMP-20x-FRR-Class-C-AFC: Addressing FedRAMP Communication",
      "FedRAMP-20x-FRR-Class-C-CMU: Cryptographic Module Use",
    ]);
    expect(items[1].items?.[0]?.key).toBe(
      "FedRAMP-20x-FRR-Class-C-CMU: Cryptographic Module Use-CMU-CSO-UVM - Using Validated Cryptographic Modules",
    );
  });
});
