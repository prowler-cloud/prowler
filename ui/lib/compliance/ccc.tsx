import { ClientAccordionContent } from "@/components/compliance/compliance-accordion/client-accordion-content";
import { ComplianceAccordionRequirementTitle } from "@/components/compliance/compliance-accordion/compliance-accordion-requeriment-title";
import { ComplianceAccordionTitle } from "@/components/compliance/compliance-accordion/compliance-accordion-title";
import { AccordionItemProps } from "@/components/ui/accordion/Accordion";
import { FindingStatus } from "@/components/ui/table/status-finding-badge";
import {
  AttributesData,
  CCCAttributesMetadata,
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
  updateCounters,
} from "./commons";

interface ProcessedItem {
  id: string;
  attrs: CCCAttributesMetadata;
  attributeItem: any;
  requirementData: any;
}

// CCC-specific section configuration
export interface CCCTextSection {
  title: string;
  key: keyof Requirement;
  className?: string;
}

export interface CCCMappingSection {
  title: string;
  key: keyof Requirement;
  colorClasses: string;
}

export const CCC_TEXT_SECTIONS: CCCTextSection[] = [
  {
    title: "Description",
    key: "description",
  },
  {
    title: "Family Description",
    key: "family_description",
  },
  {
    title: "SubSection",
    key: "subsection",
  },
  {
    title: "SubSection Objective",
    key: "subsection_objective",
    className: "whitespace-pre-wrap",
  },
  {
    title: "Recommendation",
    key: "recommendation",
    className: "whitespace-pre-wrap",
  },
];

export const CCC_MAPPING_SECTIONS: CCCMappingSection[] = [
  {
    title: "Threat Mappings",
    key: "section_threat_mappings",
    colorClasses:
      "bg-red-50 text-red-700 ring-red-600/10 dark:bg-red-400/10 dark:text-red-400 dark:ring-red-400/20",
  },
  {
    title: "Guideline Mappings",
    key: "section_guideline_mappings",
    colorClasses:
      "bg-blue-50 text-blue-700 ring-blue-600/10 dark:bg-blue-400/10 dark:text-blue-400 dark:ring-blue-400/20",
  },
];

const createRequirement = (itemData: ProcessedItem): Requirement => {
  const { id, attrs, attributeItem, requirementData } = itemData;
  const description = attributeItem.attributes.description;
  const status = requirementData.attributes.status || "";
  const checks = attributeItem.attributes.attributes.check_ids || [];
  const finalStatus: RequirementStatus = status as RequirementStatus;

  return {
    name: id,
    description: description,
    status: finalStatus,
    check_ids: checks,
    pass: finalStatus === REQUIREMENT_STATUS.PASS ? 1 : 0,
    fail: finalStatus === REQUIREMENT_STATUS.FAIL ? 1 : 0,
    manual: finalStatus === REQUIREMENT_STATUS.MANUAL ? 1 : 0,
    family_name: attrs.FamilyName,
    family_description: attrs.FamilyDescription,
    subsection: attrs.SubSection,
    subsection_objective: attrs.SubSectionObjective,
    applicability: attrs.Applicability,
    recommendation: attrs.Recommendation,
    section_threat_mappings: attrs.SectionThreatMappings,
    section_guideline_mappings: attrs.SectionGuidelineMappings,
  };
};

export const mapComplianceData = (
  attributesData: AttributesData,
  requirementsData: RequirementsData,
): Framework[] => {
  const attributes = attributesData?.data || [];
  const requirementsMap = createRequirementsMap(requirementsData);
  const frameworks: Framework[] = [];
  const itemsByFramework = new Map<string, ProcessedItem[]>();

  // First pass: collect all data
  for (const attributeItem of attributes) {
    const id = attributeItem.id;
    const metadataArray = attributeItem.attributes?.attributes
      ?.metadata as unknown as CCCAttributesMetadata[];
    const attrs = metadataArray?.[0];
    if (!attrs) continue;

    const requirementData = requirementsMap.get(id);
    if (!requirementData) continue;

    const frameworkName = attributeItem.attributes.framework;

    if (!itemsByFramework.has(frameworkName)) {
      itemsByFramework.set(frameworkName, []);
    }

    itemsByFramework.get(frameworkName)!.push({
      id,
      attrs,
      attributeItem,
      requirementData,
    });
  }

  // Process each framework
  for (const [frameworkName, items] of Array.from(itemsByFramework.entries())) {
    const framework = findOrCreateFramework(frameworks, frameworkName);

    // Group by FamilyName (Category) -> Section (Control) -> Requirements
    for (const itemData of items) {
      const requirement = createRequirement(itemData);
      const familyName = itemData.attrs.FamilyName;
      const sectionName = itemData.attrs.Section;

      // Create 3-level hierarchy: FamilyName -> Section -> Requirements
      const category = findOrCreateCategory(framework.categories, familyName);
      const control = findOrCreateControl(category.controls, sectionName);

      control.requirements.push(requirement);
      updateCounters(control, requirement.status);
    }
  }

  // Calculate counters using common helper
  calculateFrameworkCounters(frameworks);

  return frameworks;
};

// Helper function to create accordion item for requirement
const createRequirementAccordionItem = (
  requirement: Requirement,
  itemKey: string,
  scanId: string,
  frameworkName: string,
): AccordionItemProps => ({
  key: itemKey,
  title: (
    <ComplianceAccordionRequirementTitle
      type=""
      name={requirement.name}
      status={requirement.status as FindingStatus}
    />
  ),
  content: (
    <ClientAccordionContent
      key={`content-${itemKey}`}
      requirement={requirement}
      scanId={scanId}
      framework={frameworkName}
      disableFindings={
        requirement.check_ids.length === 0 && requirement.manual === 0
      }
    />
  ),
  items: [],
});

export const toAccordionItems = (
  data: Framework[],
  scanId: string | undefined,
): AccordionItemProps[] => {
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
      items: category.controls.map((control, i: number) => {
        const baseKey = `${framework.name}-${category.name}-control-${i}`;

        return {
          key: baseKey,
          title: (
            <ComplianceAccordionTitle
              label={control.label}
              pass={control.pass}
              fail={control.fail}
              manual={control.manual}
            />
          ),
          content: "",
          items: control.requirements.map((requirement, j: number) =>
            createRequirementAccordionItem(
              requirement,
              `${baseKey}-req-${j}`,
              scanId || "",
              framework.name,
            ),
          ),
          isDisabled:
            control.pass === 0 && control.fail === 0 && control.manual === 0,
        };
      }),
    })),
  );
};
