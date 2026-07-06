import { isValidElement } from "react";
import { describe, expect, it, vi } from "vitest";

// cis-controls.tsx's accordion builders transitively import the client
// accordion chain, which pulls in server-only code (next-auth) when loaded
// under vitest. Stub them the same way compliance-mapper.test.ts does —
// we're testing the mapper's data wiring, not these components' rendering.
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

import type { CrossProviderComplianceOverviewAttributes } from "@/types/compliance";

import { mapComplianceData, toAccordionItems } from "./cis-controls";
import { crossProviderToMapperInput } from "./cross-provider-adapter";

const CROSS_PROVIDER_ATTRIBUTES: CrossProviderComplianceOverviewAttributes = {
  compliance_id: "cis_controls_8.1",
  framework: "CIS-Controls",
  name: "CIS-Controls",
  version: "8.1",
  description: "CIS Critical Security Controls",
  compatible_providers: ["azure", "gcp"],
  requested_providers: ["azure", "gcp"],
  providers: ["azure", "gcp"],
  scan_ids: ["scan-azure-uuid", "scan-gcp-uuid"],
  scan_ids_by_provider: {
    azure: ["scan-azure-uuid"],
    gcp: ["scan-gcp-uuid"],
  },
  requirements_passed: 1,
  requirements_failed: 0,
  requirements_manual: 0,
  total_requirements: 1,
  requirements: [
    {
      id: "1.1",
      name: "Establish and Maintain Detailed Enterprise Asset Inventory",
      description: "Establish and maintain an inventory.",
      attributes: {
        Section: "1. Inventory and Control of Enterprise Assets",
        Function: "Identify",
        AssetType: "Devices",
        ImplementationGroups: ["IG1", "IG2", "IG3"],
      },
      status: "PASS",
      providers: { azure: "PASS", gcp: "PASS" },
      check_ids_by_provider: {
        azure: ["azure_check_a"],
        gcp: ["gcp_check_a"],
      },
    },
  ],
};

describe("cis-controls mapper — cross-provider augmentation", () => {
  it("propagates providers/check_ids_by_provider/scan_ids_by_provider onto the mapped requirement", () => {
    // This is the exact gap that made the per-provider check grouping and
    // the cross-provider findings fetch silently fall back to per-scan
    // behaviour for CIS Controls 8.1: only the CSA mapper carried these
    // fields until this fix.
    const { attributesData, requirementsData } = crossProviderToMapperInput(
      CROSS_PROVIDER_ATTRIBUTES,
    );
    const frameworks = mapComplianceData(attributesData, requirementsData);
    const requirement = frameworks[0].categories[0].controls[0].requirements[0];

    expect(requirement.providers).toEqual({ azure: "PASS", gcp: "PASS" });
    expect(requirement.check_ids_by_provider).toEqual({
      azure: ["azure_check_a"],
      gcp: ["gcp_check_a"],
    });
    expect(requirement.scan_ids_by_provider).toEqual({
      azure: ["scan-azure-uuid"],
      gcp: ["scan-gcp-uuid"],
    });
  });

  it("leaves the augmentation fields undefined for a plain per-scan requirement", () => {
    const perScanAttributesData = {
      data: [
        {
          type: "compliance-requirements-attributes" as const,
          id: "1.1",
          attributes: {
            framework_description: "",
            name: "Establish and Maintain Detailed Enterprise Asset Inventory",
            framework: "CIS-Controls",
            version: "8.1",
            description: "",
            attributes: {
              metadata: [
                {
                  Section: "1. Inventory and Control of Enterprise Assets",
                  Function: "Identify",
                  AssetType: "Devices",
                  ImplementationGroups: ["IG1"],
                },
              ],
              check_ids: ["azure_check_a"],
            },
          },
        },
      ],
    };
    const perScanRequirementsData = {
      data: [
        {
          type: "compliance-requirements-details" as const,
          id: "1.1",
          attributes: {
            framework: "CIS-Controls",
            version: "8.1",
            description: "",
            status: "PASS" as const,
          },
        },
      ],
    };

    const frameworks = mapComplianceData(
      perScanAttributesData as any,

      perScanRequirementsData as any,
    );
    const requirement = frameworks[0].categories[0].controls[0].requirements[0];

    expect(requirement.providers).toBeUndefined();
    expect(requirement.check_ids_by_provider).toBeUndefined();
    expect(requirement.scan_ids_by_provider).toBeUndefined();
  });

  it("forwards the requirement's providers map into the accordion title", () => {
    const { attributesData, requirementsData } = crossProviderToMapperInput(
      CROSS_PROVIDER_ATTRIBUTES,
    );
    const frameworks = mapComplianceData(attributesData, requirementsData);
    const items = toAccordionItems(frameworks, "");
    const titleElement = items[0]?.items?.[0]?.title;

    expect(isValidElement(titleElement)).toBe(true);
    if (isValidElement(titleElement)) {
      expect((titleElement.props as { providers?: unknown }).providers).toEqual(
        { azure: "PASS", gcp: "PASS" },
      );
    }
  });
});
