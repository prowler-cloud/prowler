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
import type {
  CrossProviderOverviewAttributes,
  CrossProviderRequirementData,
} from "@/app/(prowler)/compliance/_types";

import iso27001 from "../../../prowler/compliance/iso27001_2022.json";
import pci from "../../../prowler/compliance/pci_4.0.json";
import soc2 from "../../../prowler/compliance/soc2.json";
import { mapComplianceData as mapGenericComplianceData } from "./generic";
import { mapComplianceData as mapISOComplianceData } from "./iso";

describe.each([
  { catalog: iso27001, mapper: mapISOComplianceData },
  { catalog: soc2, mapper: mapGenericComplianceData },
  { catalog: pci, mapper: mapGenericComplianceData },
])("$catalog.framework shared catalog", ({ catalog, mapper }) => {
  it("joins every mapped control to its provider breakdown and check IDs", () => {
    // Given - Real catalog controls with two contributing scans.
    const overview: CrossProviderOverviewAttributes = {
      compliance_id: "shared-catalog",
      framework: catalog.framework,
      name: catalog.name,
      version: catalog.version,
      description: catalog.description,
      compatible_providers: ["aws", "azure"],
      requested_providers: ["aws", "azure"],
      providers: ["aws", "azure"],
      scan_ids: ["scan-aws", "scan-azure"],
      scan_ids_by_provider: { aws: ["scan-aws"], azure: ["scan-azure"] },
      requirements_passed: catalog.requirements.length,
      requirements_failed: 0,
      requirements_manual: 0,
      total_requirements: catalog.requirements.length,
      requirements: catalog.requirements.map(
        (requirement): CrossProviderRequirementData => ({
          id: requirement.id,
          name: requirement.name,
          description: requirement.description,
          attributes: requirement.attributes,
          status: "PASS",
          providers: { aws: "PASS", azure: "PASS" },
          check_ids_by_provider: requirement.checks,
        }),
      ),
    };

    // When - Adapt the roll-up through its existing framework mapper.
    const { attributesData, requirementsData } =
      crossProviderToMapperInput(overview);
    const mapped = mapper(attributesData, requirementsData).flatMap(
      (framework) =>
        framework.categories.flatMap((category) =>
          category.controls.flatMap((control) => control.requirements),
        ),
    );
    const extras = buildRequirementExtrasMap(overview);

    // Then - Details and findings links resolve for every control.
    expect(mapped).toHaveLength(catalog.requirements.length);
    for (const requirement of mapped) {
      const breakdown = extras.get(requirement.name);
      expect(breakdown, requirement.name).toBeDefined();
      expect(breakdown?.scanIdsByProvider).toEqual(
        overview.scan_ids_by_provider,
      );
      const source = overview.requirements.find(
        (control) => control.id === breakdown?.requirementId,
      );
      expect(breakdown?.providers).toEqual(source?.providers);
      expect(breakdown?.checkIdsByProvider).toEqual(
        source?.check_ids_by_provider,
      );
    }
  });
});
