import { ClientAccordionContent } from "@/components/compliance/compliance-accordion/client-accordion-content";
import { ComplianceAccordionRequirementTitle } from "@/components/compliance/compliance-accordion/compliance-accordion-requeriment-title";
import { ComplianceAccordionTitle } from "@/components/compliance/compliance-accordion/compliance-accordion-title";
import { AccordionItemProps } from "@/components/ui/accordion/Accordion";
import { FindingStatus } from "@/components/ui/table/status-finding-badge";
import {
  AttributesData,
  CISAttributesMetadata,
  Framework,
  Requirement,
  RequirementsData,
  RequirementStatus,
} from "@/types/compliance";

import {
  calculateFrameworkCounters,
  createRequirementsMap,
  findOrCreateCategory,
  findOrCreateFramework,
  updateCounters,
} from "./commons";

export const mapComplianceData = (
  attributesData: AttributesData,
  requirementsData: RequirementsData,
  filter?: string, // "Level 1" or "Level 2" or undefined (show all)
): Framework[] => {
  const attributes = attributesData?.data || [];
  const requirementsMap = createRequirementsMap(requirementsData);
  const frameworks: Framework[] = [];

  // Process attributes and merge with requirements data
  for (const attributeItem of attributes) {
    const id = attributeItem.id;
    const metadataArray = attributeItem.attributes?.attributes
      ?.metadata as unknown as CISAttributesMetadata[];
    const attrs = metadataArray?.[0];
    if (!attrs) continue;

    // Apply profile filter
    if (filter === "Level 1" && attrs.Profile !== "Level 1") {
      continue; // Skip Level 2 requirements when Level 1 is selected
    }

    // Get corresponding requirement data
    const requirementData = requirementsMap.get(id);
    if (!requirementData) continue;

    const frameworkName = attributeItem.attributes.framework;
    const sectionName = attrs.Section;
    const description = attributeItem.attributes.description;
    const status = requirementData.attributes.status || "";
    const checks = attributeItem.attributes.attributes.check_ids || [];
    const requirementName = id;

    // Find or create framework using common helper
    const framework = findOrCreateFramework(frameworks, frameworkName);

    const normalizedSectionName = sectionName.replace(/^(\d+)\s/, "$1. ");
    const category = findOrCreateCategory(
      framework.categories,
      normalizedSectionName,
    );

    // Create a control for this requirement (each requirement is its own control)
    const controlLabel = `${id} - ${description}`;
    const control = {
      label: controlLabel,
      pass: 0,
      fail: 0,
      manual: 0,
      requirements: [] as Requirement[],
    };

    // Create requirement
    const finalStatus: RequirementStatus = status as RequirementStatus;
    const requirement: Requirement = {
      name: requirementName,
      description: attrs.Description,
      status: finalStatus,
      check_ids: checks,
      pass: finalStatus === "PASS" ? 1 : 0,
      fail: finalStatus === "FAIL" ? 1 : 0,
      manual: finalStatus === "MANUAL" ? 1 : 0,
      profile: attrs.Profile,
      subsection: attrs.SubSection || "",
      assessment_status: attrs.AssessmentStatus,
      rationale_statement: attrs.RationaleStatement,
      impact_statement: attrs.ImpactStatement,
      remediation_procedure: attrs.RemediationProcedure,
      audit_procedure: attrs.AuditProcedure,
      additional_information: attrs.AdditionalInformation,
      default_value: attrs.DefaultValue || "",
      references: attrs.References,
    };

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
              />
            ),
            content: (
              <ClientAccordionContent
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
