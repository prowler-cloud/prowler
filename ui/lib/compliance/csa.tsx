import { ClientAccordionContent } from "@/components/compliance/compliance-accordion/client-accordion-content";
import { ComplianceAccordionRequirementTitle } from "@/components/compliance/compliance-accordion/compliance-accordion-requeriment-title";
import { ComplianceAccordionTitle } from "@/components/compliance/compliance-accordion/compliance-accordion-title";
import { AccordionItemProps } from "@/components/ui/accordion/Accordion";
import { FindingStatus } from "@/components/ui/table/status-finding-badge";
import {
  AttributesData,
  CSAAttributesMetadata,
  Framework,
  Requirement,
  REQUIREMENT_STATUS,
  RequirementsData,
  RequirementStatus,
} from "@/types/compliance";

import {
  calculateFrameworkCounters,
  createRequirementsMap,
  findOrCreateCategory,
  findOrCreateControl,
  findOrCreateFramework,
} from "./commons";

export interface CSAMappingSection {
  title: string;
  key: keyof Requirement;
  colorClasses: string;
}

export const CSA_MAPPING_SECTIONS: CSAMappingSection[] = [
  {
    title: "Scope Applicability",
    key: "scope_applicability",
    colorClasses:
      "bg-blue-50 text-blue-700 ring-blue-600/10 dark:bg-blue-400/10 dark:text-blue-400 dark:ring-blue-400/20",
  },
];

const getStatusCounters = (status: RequirementStatus) => ({
  pass: status === REQUIREMENT_STATUS.PASS ? 1 : 0,
  fail: status === REQUIREMENT_STATUS.FAIL ? 1 : 0,
  manual: status === REQUIREMENT_STATUS.MANUAL ? 1 : 0,
});

export const mapComplianceData = (
  attributesData: AttributesData,
  requirementsData: RequirementsData,
): Framework[] => {
  const attributes = attributesData?.data || [];
  const requirementsMap = createRequirementsMap(requirementsData);
  const frameworks: Framework[] = [];

  for (const attributeItem of attributes) {
    const id = attributeItem.id;
    const metadataArray = attributeItem.attributes?.attributes
      ?.metadata as unknown as CSAAttributesMetadata[];
    const attrs = metadataArray?.[0];
    if (!attrs) continue;

    const requirementData = requirementsMap.get(id);
    if (!requirementData) continue;

    const frameworkName = attributeItem.attributes.framework;
    const categoryName = attrs.Section;
    const requirementName = attributeItem.attributes.name || "";
    const description = attributeItem.attributes.description;
    const status = requirementData.attributes.status || "";
    const checks = attributeItem.attributes.attributes.check_ids || [];

    const framework = findOrCreateFramework(frameworks, frameworkName);
    const category = findOrCreateCategory(framework.categories, categoryName);
    // Use a single control per category to keep a flat 2-level structure
    const control = findOrCreateControl(category.controls, categoryName);

    const finalStatus: RequirementStatus = status as RequirementStatus;
    const requirement: Requirement = {
      name: requirementName ? `${id} - ${requirementName}` : id,
      description,
      status: finalStatus,
      check_ids: checks,
      ...getStatusCounters(finalStatus),
      ccm_lite: attrs.CCMLite,
      iaas: attrs.IaaS,
      paas: attrs.PaaS,
      saas: attrs.SaaS,
      scope_applicability: attrs.ScopeApplicability,
    };

    control.requirements.push(requirement);
  }

  calculateFrameworkCounters(frameworks);

  return frameworks;
};

export const toAccordionItems = (
  data: Framework[],
  scanId: string | undefined,
): AccordionItemProps[] => {
  const safeId = scanId || "";

  return data.flatMap((framework) =>
    framework.categories.map((category) => ({
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
      // Flatten: requirements are direct children of the section
      items: category.controls.flatMap((control) =>
        control.requirements.map((requirement, reqIndex) => ({
          key: `${framework.name}-${category.name}-req-${reqIndex}`,
          title: (
            <ComplianceAccordionRequirementTitle
              type=""
              name={requirement.name}
              status={requirement.status as FindingStatus}
            />
          ),
          content: (
            <ClientAccordionContent
              key={`content-${framework.name}-${category.name}-req-${reqIndex}`}
              requirement={requirement}
              scanId={safeId}
              framework={framework.name}
              disableFindings={
                requirement.check_ids.length === 0 && requirement.manual === 0
              }
            />
          ),
          items: [],
        })),
      ),
    })),
  );
};
