import { ClientAccordionContent } from "@/components/compliance/compliance-accordion/client-accordion-content";
import { ComplianceAccordionRequirementTitle } from "@/components/compliance/compliance-accordion/compliance-accordion-requeriment-title";
import { ComplianceAccordionTitle } from "@/components/compliance/compliance-accordion/compliance-accordion-title";
import { AccordionItemProps } from "@/components/ui/accordion/Accordion";
import { FindingStatus } from "@/components/ui/table/status-finding-badge";
import {
  AttributesData,
  C5AttributesMetadata,
  Control,
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

  // Process attributes and merge with requirements data
  for (const attributeItem of attributes) {
    const id = attributeItem.id;
    const metadataArray = attributeItem.attributes?.attributes
      ?.metadata as unknown as C5AttributesMetadata[];
    const attrs = metadataArray?.[0];
    if (!attrs) continue;

    // Get corresponding requirement data
    const requirementData = requirementsMap.get(id);
    if (!requirementData) continue;

    const frameworkName = attributeItem.attributes.framework;
    const categoryName = attrs.Section; // Level 1: Section (e.g., "Organisation of Information Security (OIS)")
    const controlLabel = attrs.SubSection; // Level 2: SubSection (e.g., "OIS-01 Information Security Management System (ISMS)")
    const description = attributeItem.attributes.description;
    const status = requirementData.attributes.status || "";
    const checks = attributeItem.attributes.attributes.check_ids || [];
    const requirementName = id;

    // Find or create framework using common helper
    const framework = findOrCreateFramework(frameworks, frameworkName);

    // Find or create category (Section) using common helper
    const category = findOrCreateCategory(framework.categories, categoryName);

    // Find or create control (SubSection) using common helper
    const control = findOrCreateControl(category.controls, controlLabel);

    // Create requirement
    const finalStatus: RequirementStatus = status as RequirementStatus;
    const requirement: Requirement = {
      name: requirementName,
      description,
      status: finalStatus,
      check_ids: checks,
      ...getStatusCounters(finalStatus),
      type: attrs.Type,
      about_criteria: attrs.AboutCriteria,
      complementary_criteria: attrs.ComplementaryCriteria,
    };

    control.requirements.push(requirement);
  }

  // Calculate counters using common helper
  calculateFrameworkCounters(frameworks);

  return frameworks;
};

const createRequirementItem = (
  requirement: Requirement,
  frameworkName: string,
  categoryName: string,
  controlIndex: number,
  reqIndex: number,
  scanId: string,
): AccordionItemProps => ({
  key: `${frameworkName}-${categoryName}-control-${controlIndex}-req-${reqIndex}`,
  title: (
    <ComplianceAccordionRequirementTitle
      type={requirement.type as string}
      name={requirement.name}
      status={requirement.status as FindingStatus}
    />
  ),
  content: (
    <ClientAccordionContent
      key={`content-${frameworkName}-${categoryName}-control-${controlIndex}-req-${reqIndex}`}
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

const createControlItem = (
  control: Control,
  frameworkName: string,
  categoryName: string,
  controlIndex: number,
  scanId: string,
): AccordionItemProps => ({
  key: `${frameworkName}-${categoryName}-control-${controlIndex}`,
  title: (
    <ComplianceAccordionTitle
      label={control.label}
      pass={control.pass}
      fail={control.fail}
      manual={control.manual}
    />
  ),
  content: "",
  items: control.requirements.map((requirement, reqIndex) =>
    createRequirementItem(
      requirement,
      frameworkName,
      categoryName,
      controlIndex,
      reqIndex,
      scanId,
    ),
  ),
  isDisabled: control.pass === 0 && control.fail === 0 && control.manual === 0,
});

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
      items: category.controls.map((control, controlIndex) =>
        createControlItem(
          control,
          framework.name,
          category.name,
          controlIndex,
          safeId,
        ),
      ),
    })),
  );
};
