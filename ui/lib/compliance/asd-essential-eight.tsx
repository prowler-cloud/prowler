import { ClientAccordionContent } from "@/components/compliance/compliance-accordion/client-accordion-content";
import { ComplianceAccordionRequirementTitle } from "@/components/compliance/compliance-accordion/compliance-accordion-requeriment-title";
import { ComplianceAccordionTitle } from "@/components/compliance/compliance-accordion/compliance-accordion-title";
import type { AccordionItemProps } from "@/components/shadcn/accordion/Accordion";
import type { FindingStatus } from "@/components/shadcn/table/status-finding-badge";
import {
  type ASDEssentialEightRequirement,
  type AttributesData,
  type Framework,
  isASDEssentialEightAttributesMetadata,
  type Requirement,
  REQUIREMENT_STATUS,
  type RequirementsData,
} from "@/types/compliance";

import {
  calculateFrameworkCounters,
  createRequirementsMap,
  findOrCreateCategory,
  findOrCreateFramework,
  updateCounters,
} from "./commons";

// TODO(PROWLER-1470): `_filter` is reserved for future Maturity Level
// filtering (analogous to CIS's Profile filter). Today the JSON only
// contains ML1 requirements, so the parameter is a no-op; once ML2/ML3
// ship, mirror the CIS pattern of skipping requirements whose
// `attrs.MaturityLevel` !== filter. The leading underscore tells eslint
// and TypeScript-ESLint that the parameter is intentionally unused.
export const mapComplianceData = (
  attributesData: AttributesData,
  requirementsData: RequirementsData,
  _filter?: string,
): Framework[] => {
  const attributes = attributesData?.data || [];
  const requirementsMap = createRequirementsMap(requirementsData);
  const frameworks: Framework[] = [];

  // Process attributes and merge with requirements data
  for (const attributeItem of attributes) {
    const id = attributeItem.id;
    const metadataArray = attributeItem.attributes?.attributes?.metadata;
    const attrs = metadataArray?.[0];
    if (!isASDEssentialEightAttributesMetadata(attrs)) continue;

    // Get corresponding requirement data
    const requirementData = requirementsMap.get(id);
    if (!requirementData) continue;

    const frameworkName = attributeItem.attributes.framework;
    const sectionName = attrs.Section;
    const description = attributeItem.attributes.description;
    const status = requirementData.attributes.status;
    const checks = attributeItem.attributes.attributes.check_ids;
    const requirementName = id;

    // Find or create framework using common helper
    const framework = findOrCreateFramework(frameworks, frameworkName);

    // Sections in the source JSON are formatted "1 Patch applications";
    // normalize to "1. Patch applications" so the leading clause number reads
    // as a sentence in the accordion header. Order is preserved by JSON
    // document order (categories materialize in insertion order via
    // `findOrCreateCategory`); this rewrite is purely cosmetic.
    const normalizedSectionName = sectionName.replace(/^(\d+)\s/, "$1. ");
    const category = findOrCreateCategory(
      framework.categories,
      normalizedSectionName,
    );

    // Each requirement is its own control (matches CIS rendering): keeps
    // the framework's clause-level granularity visible in the accordion.
    // The accordion title and the requirement.description must surface the
    // *literal ASD clause* (`description`, the canonical standard text).
    // The Attributes[].Description field carries Prowler's
    // provider-specific implementation note; we expose it separately as
    // `implementation_notes` so the details panel can render it under
    // "Implementation Notes" without coupling the field to a single
    // provider.
    const controlLabel = `${id} - ${description}`;
    const control = {
      label: controlLabel,
      pass: 0,
      fail: 0,
      manual: 0,
      requirements: [] as Requirement[],
    };

    const requirement = {
      name: requirementName,
      description: description,
      status: status,
      check_ids: checks,
      invalid_config: requirementData.attributes.invalid_config || false,
      pass: status === REQUIREMENT_STATUS.PASS ? 1 : 0,
      fail: status === REQUIREMENT_STATUS.FAIL ? 1 : 0,
      manual: status === REQUIREMENT_STATUS.MANUAL ? 1 : 0,
      maturity_level: attrs.MaturityLevel,
      assessment_status: attrs.AssessmentStatus,
      cloud_applicability: attrs.CloudApplicability,
      mitigated_threats: attrs.MitigatedThreats,
      implementation_notes: attrs.Description,
      rationale_statement: attrs.RationaleStatement,
      impact_statement: attrs.ImpactStatement,
      remediation_procedure: attrs.RemediationProcedure,
      audit_procedure: attrs.AuditProcedure,
      additional_information: attrs.AdditionalInformation,
      references: attrs.References,
    } satisfies ASDEssentialEightRequirement;

    control.requirements.push(requirement);

    // Update control counters using common helper
    updateCounters(control, requirement.status);

    category.controls.push(control);
  }

  // Calculate counters using common helper
  calculateFrameworkCounters(frameworks);

  return frameworks;
};

export const toAccordionItems = (
  data: Framework[],
  scanId: string | undefined,
): AccordionItemProps[] => {
  return data.flatMap((framework) =>
    framework.categories.map((category) => {
      return {
        key: `${framework.name}-${category.name}`,
        title: (
          <ComplianceAccordionTitle
            label={category.name}
            pass={category.pass}
            fail={category.fail}
            manual={category.manual}
            isParentLevel={true}
          />
        ),
        content: "",
        items: category.controls.map((control, i: number) => {
          const requirement = control.requirements[0]; // Each control has one requirement
          const itemKey = `${framework.name}-${category.name}-control-${i}`;

          return {
            key: itemKey,
            title: (
              <ComplianceAccordionRequirementTitle
                type=""
                name={control.label}
                status={requirement.status as FindingStatus}
                invalidConfig={requirement.invalid_config}
              />
            ),
            content: (
              <ClientAccordionContent
                key={`content-${itemKey}`}
                requirement={requirement}
                scanId={scanId || ""}
                framework={framework.name}
                disableFindings={
                  requirement.check_ids.length === 0 && requirement.manual === 0
                }
              />
            ),
            items: [],
          };
        }),
      };
    }),
  );
};
