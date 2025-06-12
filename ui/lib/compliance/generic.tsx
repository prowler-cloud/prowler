import { ClientAccordionContent } from "@/components/compliance/compliance-accordion/client-accordion-content";
import { ComplianceAccordionRequirementTitle } from "@/components/compliance/compliance-accordion/compliance-accordion-requeriment-title";
import { ComplianceAccordionTitle } from "@/components/compliance/compliance-accordion/compliance-accordion-title";
import { AccordionItemProps } from "@/components/ui/accordion/Accordion";
import { FindingStatus } from "@/components/ui/table/status-finding-badge";
import {
  AttributesData,
  Framework,
  GenericAttributesMetadata,
  Requirement,
  RequirementItemData,
  RequirementsData,
  RequirementStatus,
} from "@/types/compliance";

import { updateCounters } from "./commons";

interface ProcessedItem {
  id: string;
  attrs: GenericAttributesMetadata;
  attributeItem: any;
  requirementData: RequirementItemData;
}

const createRequirement = (itemData: ProcessedItem): Requirement => {
  const { id, attrs, attributeItem, requirementData } = itemData;
  const requirementName = attributeItem.attributes.name || id;
  const description = attributeItem.attributes.description;
  const status = requirementData.attributes.status || "";
  const checks = attributeItem.attributes.attributes.check_ids || [];
  const finalStatus: RequirementStatus = status as RequirementStatus;

  return {
    name: requirementName,
    description: description,
    status: finalStatus,
    check_ids: checks,
    pass: finalStatus === "PASS" ? 1 : 0,
    fail: finalStatus === "FAIL" ? 1 : 0,
    manual: finalStatus === "MANUAL" ? 1 : 0,
    item_id: attrs.ItemId,
    subsection: attrs.SubSection,
    subgroup: attrs.SubGroup || undefined,
    service: attrs.Service || undefined,
    type: attrs.Type || undefined,
  };
};

const findOrCreateFramework = (
  frameworks: Framework[],
  frameworkName: string,
): Framework => {
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
  return framework;
};

const findOrCreateCategory = (categories: any[], categoryName: string) => {
  let category = categories.find((c) => c.name === categoryName);
  if (!category) {
    category = {
      name: categoryName,
      pass: 0,
      fail: 0,
      manual: 0,
      controls: [],
    };
    categories.push(category);
  }
  return category;
};

const findOrCreateControl = (controls: any[], controlLabel: string) => {
  let control = controls.find((c) => c.label === controlLabel);
  if (!control) {
    control = {
      label: controlLabel,
      pass: 0,
      fail: 0,
      manual: 0,
      requirements: [],
    };
    controls.push(control);
  }
  return control;
};

const shouldUseThreeLevelHierarchy = (items: ProcessedItem[]): boolean => {
  const itemsWithSection = items.filter(
    (item) =>
      item.attrs.Section &&
      item.attrs.Section !== (item.attributeItem.attributes.name || item.id),
  );
  return (
    itemsWithSection.length > 0 &&
    itemsWithSection.every((item) => item.attrs.SubSection)
  );
};

export const mapComplianceData = (
  attributesData: AttributesData,
  requirementsData: RequirementsData,
): Framework[] => {
  const attributes = attributesData?.data || [];
  const requirements = requirementsData?.data || [];

  // Create a map for quick lookup of requirements by id
  const requirementsMap = new Map<string, RequirementItemData>();
  requirements.forEach((req: RequirementItemData) => {
    requirementsMap.set(req.id, req);
  });

  const frameworks: Framework[] = [];
  const itemsByFramework = new Map<string, ProcessedItem[]>();

  // First pass: collect all data
  for (const attributeItem of attributes) {
    const id = attributeItem.id;
    const metadataArray = attributeItem.attributes?.attributes
      ?.metadata as unknown as GenericAttributesMetadata[];
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
    const allHaveSubsection = shouldUseThreeLevelHierarchy(items);

    // Process each item in the framework
    for (const itemData of items) {
      const requirement = createRequirement(itemData);
      const requirementName =
        itemData.attributeItem.attributes.name || itemData.id;
      const sectionName = itemData.attrs.Section;
      const subSectionName = itemData.attrs.SubSection;

      // Determine structure: flat, 2-level, or 3-level hierarchy
      if (!sectionName || sectionName === requirementName) {
        // Flat structure: store requirements directly in framework
        (framework as any).requirements = (framework as any).requirements || [];
        (framework as any).requirements.push(requirement);
        updateCounters(framework, requirement.status);
      } else if (allHaveSubsection && subSectionName) {
        // 3-level hierarchy: Section -> SubSection -> Requirements
        const category = findOrCreateCategory(
          framework.categories,
          sectionName,
        );
        const control = findOrCreateControl(category.controls, subSectionName);
        control.requirements.push(requirement);
        updateCounters(control, requirement.status);
      } else {
        // 2-level hierarchy: Section -> Requirements
        const category = findOrCreateCategory(
          framework.categories,
          sectionName,
        );
        const control = {
          label: requirementName,
          pass: 0,
          fail: 0,
          manual: 0,
          requirements: [requirement],
        };
        updateCounters(control, requirement.status);
        category.controls.push(control);
      }
    }
  }

  // Calculate counters for hierarchical structures
  frameworks.forEach((framework) => {
    if (framework.categories.length > 0) {
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
    }
  });

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
  return data.flatMap((framework) => {
    const directRequirements = (framework as any).requirements || [];

    // Flat structure - requirements directly
    if (directRequirements.length > 0) {
      return directRequirements.map((requirement: Requirement, i: number) =>
        createRequirementAccordionItem(
          requirement,
          `${framework.name}-req-${i}`,
          scanId || "",
          framework.name,
        ),
      );
    }

    // Hierarchical structure - categories with controls
    return framework.categories.map((category) => ({
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

        // 3-level hierarchy: control has multiple requirements
        if (control.requirements.length > 1) {
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
        }

        // 2-level hierarchy: direct requirement
        const requirement = control.requirements[0];
        return {
          key: baseKey,
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
    }));
  });
};
