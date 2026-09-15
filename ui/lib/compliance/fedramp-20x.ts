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

export { toGroupedAccordionItems as toAccordionItems } from "./grouped-accordion";

type RequirementFields = Record<string, string | undefined>;

const getStatusCounters = (status: RequirementStatus) => ({
  pass: status === REQUIREMENT_STATUS.PASS ? 1 : 0,
  fail: status === REQUIREMENT_STATUS.FAIL ? 1 : 0,
  manual: status === REQUIREMENT_STATUS.MANUAL ? 1 : 0,
});

const mapByGroup = <TMetadata>(
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
