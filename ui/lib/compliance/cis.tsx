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
  RequirementItemData,
  RequirementsData,
  RequirementStatus,
} from "@/types/compliance";

export const mapComplianceData = (
  attributesData: AttributesData,
  requirementsData: RequirementsData,
  filter?: string, // "Level 1" or "Level 2" or undefined (show all)
): Framework[] => {
  const attributes = attributesData?.data || [];
  const requirements = requirementsData?.data || [];

  // Create a map for quick lookup of requirements by id
  const requirementsMap = new Map<string, RequirementItemData>();
  requirements.forEach((req: RequirementItemData) => {
    requirementsMap.set(req.id, req);
  });

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

    // Find or create framework
    let framework = frameworks.find((f) => f.name === frameworkName);
    if (!framework) {
      framework = {
        name: frameworkName,
        pass: 0,
        fail: 0,
        manual: 0,
        categories: [],
      };
      frameworks.push(framework);
    }

    const normalizedSectionName = sectionName.replace(/^(\d+)\s/, "$1. ");
    let category = framework.categories.find(
      (c) => c.name === normalizedSectionName,
    );

    if (!category) {
      category = {
        name: normalizedSectionName,
        pass: 0,
        fail: 0,
        manual: 0,
        controls: [],
      };
      framework.categories.push(category);
    }

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

    // Update control counters
    if (requirement.status === "MANUAL") {
      control.manual++;
    } else if (requirement.status === "PASS") {
      control.pass++;
    } else if (requirement.status === "FAIL") {
      control.fail++;
    }

    category.controls.push(control);
  }

  // Calculate counters for categories and frameworks
  frameworks.forEach((framework) => {
    framework.pass = 0;
    framework.fail = 0;
    framework.manual = 0;

    framework.categories.forEach((category) => {
      category.pass = 0;
      category.fail = 0;
      category.manual = 0;

      category.controls.forEach((control) => {
        category.pass += control.pass;
        category.fail += control.fail;
        category.manual += control.manual;
      });

      framework.pass += category.pass;
      framework.fail += category.fail;
      framework.manual += category.manual;
    });
  });

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
