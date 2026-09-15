import { ClientAccordionContent } from "@/components/compliance/compliance-accordion/client-accordion-content";
import { ComplianceAccordionRequirementTitle } from "@/components/compliance/compliance-accordion/compliance-accordion-requeriment-title";
import { ComplianceAccordionTitle } from "@/components/compliance/compliance-accordion/compliance-accordion-title";
import { AccordionItemProps } from "@/components/shadcn/accordion/Accordion";
import { FindingStatus } from "@/components/shadcn/table/status-finding-badge";
import {
  AttributesData,
  FedRAMP20xFRRAttributesMetadata,
  FedRAMP20xKSIAttributesMetadata,
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

type RequirementFields = Record<string, string | undefined>;

const getStatusCounters = (status: RequirementStatus) => ({
  pass: status === REQUIREMENT_STATUS.PASS ? 1 : 0,
  fail: status === REQUIREMENT_STATUS.FAIL ? 1 : 0,
  manual: status === REQUIREMENT_STATUS.MANUAL ? 1 : 0,
});

const mapByGroup = <TMetadata,>(
  attributesData: AttributesData,
  requirementsData: RequirementsData,
  getGroup: (attrs: TMetadata) => string,
  getFields: (attrs: TMetadata) => RequirementFields,
): Framework[] => {
  const attributes = attributesData?.data || [];
  const requirementsMap = createRequirementsMap(requirementsData);
  const frameworks: Framework[] = [];

  for (const attributeItem of attributes) {
    const id = attributeItem.id;
    const metadataArray = attributeItem.attributes?.attributes
      ?.metadata as unknown as TMetadata[];
    const attrs = metadataArray?.[0];
    if (!attrs) continue;

    const requirementData = requirementsMap.get(id);
    if (!requirementData) continue;

    const categoryName = getGroup(attrs);
    const requirementName = attributeItem.attributes.name || "";
    const status = (requirementData.attributes.status ||
      "") as RequirementStatus;

    const framework = findOrCreateFramework(
      frameworks,
      attributeItem.attributes.framework,
    );
    const category = findOrCreateCategory(framework.categories, categoryName);
    const control = findOrCreateControl(category.controls, categoryName);

    // The name must match `composeRequirementName` in the cross-provider
    // adapter, or the per-provider breakdown cannot be joined.
    const requirement: Requirement = {
      ...getFields(attrs),
      name: requirementName ? `${id} - ${requirementName}` : id,
      description: attributeItem.attributes.description,
      status,
      check_ids: attributeItem.attributes.attributes.check_ids || [],
      invalid_config: requirementData.attributes.invalid_config || false,
      ...getStatusCounters(status),
    };

    control.requirements.push(requirement);
  }

  // Theme and Ruleset names start with their catalog code, so alphabetical
  // order is the catalog order.
  for (const framework of frameworks) {
    framework.categories.sort((a, b) => a.name.localeCompare(b.name));
  }

  calculateFrameworkCounters(frameworks);

  return frameworks;
};

export const mapKSIComplianceData = (
  attributesData: AttributesData,
  requirementsData: RequirementsData,
): Framework[] =>
  mapByGroup<FedRAMP20xKSIAttributesMetadata>(
    attributesData,
    requirementsData,
    (attrs) => attrs.Theme,
    (attrs) => ({
      theme: attrs.Theme,
      nist_controls: attrs.NISTControls || undefined,
      class_applicability: attrs.ClassApplicability,
    }),
  );

export const mapFRRComplianceData = (
  attributesData: AttributesData,
  requirementsData: RequirementsData,
): Framework[] =>
  mapByGroup<FedRAMP20xFRRAttributesMetadata>(
    attributesData,
    requirementsData,
    (attrs) => attrs.Ruleset,
    (attrs) => ({
      ruleset: attrs.Ruleset,
      subset: attrs.Subset,
      force: attrs.Force,
    }),
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
      items: category.controls.flatMap((control) =>
        control.requirements.map((requirement) => ({
          key: `${framework.name}-${category.name}-${requirement.name}`,
          title: (
            <ComplianceAccordionRequirementTitle
              type=""
              name={requirement.name}
              status={requirement.status as FindingStatus}
              invalidConfig={requirement.invalid_config}
            />
          ),
          content: (
            <ClientAccordionContent
              key={`content-${framework.name}-${category.name}-${requirement.name}`}
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
