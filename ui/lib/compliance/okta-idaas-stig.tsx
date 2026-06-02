import { ClientAccordionContent } from "@/components/compliance/compliance-accordion/client-accordion-content";
import { ComplianceAccordionRequirementTitle } from "@/components/compliance/compliance-accordion/compliance-accordion-requeriment-title";
import { ComplianceAccordionTitle } from "@/components/compliance/compliance-accordion/compliance-accordion-title";
import { AccordionItemProps } from "@/components/ui/accordion/Accordion";
import { FindingStatus } from "@/components/ui/table/status-finding-badge";
import {
  AttributesData,
  Control,
  Framework,
  OktaIDaaSStigAttributesMetadata,
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

  for (const attributeItem of attributes) {
    const id = attributeItem.id;
    const metadataArray = attributeItem.attributes?.attributes
      ?.metadata as unknown as OktaIDaaSStigAttributesMetadata[];
    const attrs = metadataArray?.[0];
    if (!attrs) continue;

    const requirementData = requirementsMap.get(id);
    if (!requirementData) continue;

    const frameworkName = attributeItem.attributes.framework;
    // Level 1: Section maps to the STIG severity category (e.g. "CAT II (Medium)")
    const categoryName = attrs.Section;
    // Level 2: each requirement is its own control, labelled by its STIG ID
    const controlLabel = id;
    const description = attributeItem.attributes.description;
    const status = requirementData.attributes.status || "";
    const checks = attributeItem.attributes.attributes.check_ids || [];

    const framework = findOrCreateFramework(frameworks, frameworkName);
    const category = findOrCreateCategory(framework.categories, categoryName);
    const control = findOrCreateControl(category.controls, controlLabel);

    const finalStatus: RequirementStatus = status as RequirementStatus;
    const requirement: Requirement = {
      name: id,
      description,
      status: finalStatus,
      check_ids: checks,
      ...getStatusCounters(finalStatus),
      severity: attrs.Severity,
      rule_id: attrs.RuleID,
      stig_id: attrs.StigID,
      cci: attrs.CCI,
      check_text: attrs.CheckText,
      fix_text: attrs.FixText,
    };

    control.requirements.push(requirement);
  }

  calculateFrameworkCounters(frameworks);

  return frameworks;
};

const createRequirementItem = (
  requirement: Requirement,
  frameworkName: string,
  categoryName: string,
  controlIndex: number,
  scanId: string,
): AccordionItemProps => ({
  key: `${frameworkName}-${categoryName}-control-${controlIndex}`,
  title: (
    <ComplianceAccordionRequirementTitle
      type={requirement.severity as string}
      name={requirement.name}
      status={requirement.status as FindingStatus}
    />
  ),
  content: (
    <ClientAccordionContent
      key={`content-${frameworkName}-${categoryName}-control-${controlIndex}`}
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
): AccordionItemProps =>
  createRequirementItem(
    control.requirements[0],
    frameworkName,
    categoryName,
    controlIndex,
    scanId,
  );

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
