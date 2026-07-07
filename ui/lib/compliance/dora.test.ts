import { isValidElement } from "react";
import { describe, expect, it, vi } from "vitest";

// dora.tsx's accordion builders transitively import the client accordion
// chain, which pulls in server-only code (next-auth) when loaded under
// vitest. Stub them the same way compliance-mapper.test.ts does — we're
// testing the mapper's data wiring, not these components' rendering.
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

import type {
  AttributesData,
  CrossProviderComplianceOverviewAttributes,
  RequirementsData,
} from "@/types/compliance";

import { crossProviderToMapperInput } from "./cross-provider-adapter";
import { mapComplianceData, toAccordionItems } from "./dora";

const CROSS_PROVIDER_ATTRIBUTES: CrossProviderComplianceOverviewAttributes = {
  compliance_id: "dora_2022_2554",
  framework: "DORA",
  name: "DORA",
  version: "2022/2554",
  description: "Digital Operational Resilience Act",
  compatible_providers: ["aws", "azure"],
  requested_providers: ["aws", "azure"],
  providers: ["aws", "azure"],
  scan_ids: ["scan-aws-uuid", "scan-azure-uuid"],
  scan_ids_by_provider: {
    aws: ["scan-aws-uuid"],
    azure: ["scan-azure-uuid"],
  },
  requirements_passed: 1,
  requirements_failed: 0,
  requirements_manual: 0,
  total_requirements: 1,
  requirements: [
    {
      id: "Art-5",
      name: "ICT risk management framework",
      description: "Maintain a sound ICT risk management framework.",
      attributes: {
        Pillar: "ICT Risk Management",
        Article: "5",
        ArticleTitle: "ICT risk management framework",
      },
      status: "PASS",
      providers: { aws: "PASS", azure: "PASS" },
      check_ids_by_provider: {
        aws: ["aws_check_a"],
        azure: ["azure_check_a"],
      },
    },
  ],
};

describe("dora mapper — cross-provider augmentation", () => {
  it("propagates providers/check_ids_by_provider/scan_ids_by_provider onto the mapped requirement", () => {
    // Same gap fixed for CIS Controls: only the CSA mapper carried these
    // fields until this fix, silently breaking per-provider check grouping
    // and the cross-provider findings fetch for DORA.
    const { attributesData, requirementsData } = crossProviderToMapperInput(
      CROSS_PROVIDER_ATTRIBUTES,
    );
    const frameworks = mapComplianceData(attributesData, requirementsData);
    const requirement = frameworks[0].categories[0].controls[0].requirements[0];

    expect(requirement.providers).toEqual({ aws: "PASS", azure: "PASS" });
    expect(requirement.check_ids_by_provider).toEqual({
      aws: ["aws_check_a"],
      azure: ["azure_check_a"],
    });
    expect(requirement.scan_ids_by_provider).toEqual({
      aws: ["scan-aws-uuid"],
      azure: ["scan-azure-uuid"],
    });
  });

  it("leaves the augmentation fields undefined for a plain per-scan requirement", () => {
    const perScanAttributesData = {
      data: [
        {
          type: "compliance-requirements-attributes" as const,
          id: "Art-5",
          attributes: {
            framework_description: "",
            name: "ICT risk management framework",
            framework: "DORA",
            version: "2022/2554",
            description: "",
            attributes: {
              metadata: [
                {
                  Pillar: "ICT Risk Management",
                  Article: "5",
                  ArticleTitle: "ICT risk management framework",
                },
              ],
              check_ids: ["aws_check_a"],
            },
          },
        },
      ],
    };
    const perScanRequirementsData = {
      data: [
        {
          type: "compliance-requirements-details" as const,
          id: "Art-5",
          attributes: {
            framework: "DORA",
            version: "2022/2554",
            description: "",
            status: "PASS" as const,
          },
        },
      ],
    };

    const frameworks = mapComplianceData(
      perScanAttributesData as unknown as AttributesData,
      perScanRequirementsData as unknown as RequirementsData,
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
        { aws: "PASS", azure: "PASS" },
      );
    }
  });
});
