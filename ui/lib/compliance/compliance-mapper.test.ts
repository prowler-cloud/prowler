import { isValidElement, ReactElement } from "react";
import { describe, expect, it, vi } from "vitest";

// Custom-details components and the `ClientAccordionContent` chain
// transitively import server-only code (next-auth → next/server). Mocking
// them with identifiable stubs lets us load the registry under vitest and
// assert that `getDetailsComponent` returns the *correct* stub for each
// framework — i.e. that the wiring is actually behavioral.
type DetailsStubProps = { requirement: { name?: string } };

// `vi.hoisted` runs *before* the hoisted `vi.mock` factories, so we can
// safely close over `stubFactory` from inside each mock without tripping
// the temporal-dead-zone error vitest raises for top-level helpers.
const { stubFactory } = vi.hoisted(() => ({
  stubFactory: (label: string) => {
    const Stub = (_props: DetailsStubProps) => null;
    Stub.displayName = label;
    return Stub;
  },
}));

vi.mock(
  "@/components/compliance/compliance-custom-details/asd-essential-eight-details",
  () => ({ ASDEssentialEightCustomDetails: stubFactory("ASDStub") }),
);
vi.mock(
  "@/components/compliance/compliance-custom-details/aws-well-architected-details",
  () => ({ AWSWellArchitectedCustomDetails: stubFactory("AWSWAStub") }),
);
vi.mock("@/components/compliance/compliance-custom-details/c5-details", () => ({
  C5CustomDetails: stubFactory("C5Stub"),
}));
vi.mock(
  "@/components/compliance/compliance-custom-details/ccc-details",
  () => ({ CCCCustomDetails: stubFactory("CCCStub") }),
);
vi.mock(
  "@/components/compliance/compliance-custom-details/cis-details",
  () => ({ CISCustomDetails: stubFactory("CISStub") }),
);
vi.mock(
  "@/components/compliance/compliance-custom-details/csa-details",
  () => ({ CSACustomDetails: stubFactory("CSAStub") }),
);
vi.mock(
  "@/components/compliance/compliance-custom-details/ens-details",
  () => ({ ENSCustomDetails: stubFactory("ENSStub") }),
);
vi.mock(
  "@/components/compliance/compliance-custom-details/generic-details",
  () => ({ GenericCustomDetails: stubFactory("GenericStub") }),
);
vi.mock(
  "@/components/compliance/compliance-custom-details/iso-details",
  () => ({ ISOCustomDetails: stubFactory("ISOStub") }),
);
vi.mock(
  "@/components/compliance/compliance-custom-details/kisa-details",
  () => ({ KISACustomDetails: stubFactory("KISAStub") }),
);
vi.mock(
  "@/components/compliance/compliance-custom-details/mitre-details",
  () => ({ MITRECustomDetails: stubFactory("MITREStub") }),
);
vi.mock(
  "@/components/compliance/compliance-custom-details/okta-idaas-stig-details",
  () => ({ OktaIDaaSStigCustomDetails: stubFactory("OktaIDaaSStigStub") }),
);
vi.mock(
  "@/components/compliance/compliance-custom-details/threat-details",
  () => ({ ThreatCustomDetails: stubFactory("ThreatStub") }),
);

// Each per-framework mapper file (cis.tsx, ens.tsx, etc.) re-exports JSX
// builders that pull in the same client-side accordion chain. Stub them
// out so the registry module can load without booting Next's server-only
// runtime — the registry is what we actually test here.
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

import { Requirement } from "@/types/compliance";

import { getComplianceMapper } from "./compliance-mapper";

const fakeRequirement: Requirement = {
  name: "test",
  description: "test",
  status: "PASS",
  pass: 1,
  fail: 0,
  manual: 0,
  check_ids: [],
};

const detailsStubName = (component: unknown): string | undefined => {
  if (!isValidElement(component)) return undefined;
  // `type` of a React element holds the component function (the stub we
  // registered above); `displayName` is what we keyed each stub on.
  const element = component as ReactElement<DetailsStubProps>;
  const type = element.type as { displayName?: string };
  return type.displayName;
};

describe("getComplianceMapper", () => {
  it("falls back to the generic mapper when no framework is supplied", () => {
    const mapper = getComplianceMapper(undefined);
    expect(detailsStubName(mapper.getDetailsComponent(fakeRequirement))).toBe(
      "GenericStub",
    );
  });

  it("falls back to the generic mapper for an unknown framework", () => {
    const mapper = getComplianceMapper("Made-Up-Framework");
    expect(detailsStubName(mapper.getDetailsComponent(fakeRequirement))).toBe(
      "GenericStub",
    );
  });

  it("wires each registered framework to its dedicated details component", () => {
    // The keys MUST match the `framework` field the API returns
    // (case- and hyphen-sensitive).
    const wiring: Array<{ framework: string; expected: string }> = [
      { framework: "ASD-Essential-Eight", expected: "ASDStub" },
      { framework: "C5", expected: "C5Stub" },
      { framework: "ENS", expected: "ENSStub" },
      { framework: "ISO27001", expected: "ISOStub" },
      { framework: "CIS", expected: "CISStub" },
      {
        framework: "AWS-Well-Architected-Framework-Security-Pillar",
        expected: "AWSWAStub",
      },
      {
        framework: "AWS-Well-Architected-Framework-Reliability-Pillar",
        expected: "AWSWAStub",
      },
      { framework: "KISA-ISMS-P", expected: "KISAStub" },
      { framework: "MITRE-ATTACK", expected: "MITREStub" },
      { framework: "ProwlerThreatScore", expected: "ThreatStub" },
      { framework: "CCC", expected: "CCCStub" },
      { framework: "CSA-CCM", expected: "CSAStub" },
      { framework: "Okta-IDaaS-STIG", expected: "OktaIDaaSStigStub" },
    ];

    for (const { framework, expected } of wiring) {
      const mapper = getComplianceMapper(framework);
      expect(
        detailsStubName(mapper.getDetailsComponent(fakeRequirement)),
        `framework "${framework}" should resolve to ${expected}`,
      ).toBe(expected);
    }
  });

  it("exposes the four functions every consumer relies on", () => {
    const mapper = getComplianceMapper("ASD-Essential-Eight");
    expect(typeof mapper.mapComplianceData).toBe("function");
    expect(typeof mapper.toAccordionItems).toBe("function");
    expect(typeof mapper.getTopFailedSections).toBe("function");
    expect(typeof mapper.calculateCategoryHeatmapData).toBe("function");
    expect(typeof mapper.getDetailsComponent).toBe("function");
  });

  it("returns the same reference shape for every supported framework", () => {
    // A regression sentinel: if a future entry forgets one of the five
    // functions the registry contract requires, this assertion catches
    // it before the runtime errors leak into the UI.
    const expectedKeys = [
      "mapComplianceData",
      "toAccordionItems",
      "getTopFailedSections",
      "calculateCategoryHeatmapData",
      "getDetailsComponent",
    ].sort();

    for (const framework of [
      "ASD-Essential-Eight",
      "C5",
      "ENS",
      "ISO27001",
      "CIS",
      "AWS-Well-Architected-Framework-Security-Pillar",
      "KISA-ISMS-P",
      "MITRE-ATTACK",
      "ProwlerThreatScore",
      "CCC",
      "CSA-CCM",
      "Okta-IDaaS-STIG",
    ]) {
      const mapper = getComplianceMapper(framework);
      expect(Object.keys(mapper).sort(), framework).toEqual(expectedKeys);
    }
  });
});
