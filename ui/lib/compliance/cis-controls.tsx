import { ClientAccordionContent } from "@/components/compliance/compliance-accordion/client-accordion-content";
import { ComplianceAccordionRequirementTitle } from "@/components/compliance/compliance-accordion/compliance-accordion-requeriment-title";
import { ComplianceAccordionTitle } from "@/components/compliance/compliance-accordion/compliance-accordion-title";
import { AccordionItemProps } from "@/components/shadcn/accordion/Accordion";
import { FindingStatus } from "@/components/shadcn/table/status-finding-badge";
import {
  AttributesData,
  CISControlsAttributesMetadata,
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

// Sort the 18 CIS Controls by their leading number ("1. ...", "2. ...", ...,
// "18. ...") so the accordion always reads in canonical control order
// regardless of how the API returns the sections.
const sectionOrder = (section: string): number => {
  const match = section.match(/^(\d+)/);
  return match ? parseInt(match[1], 10) : Number.MAX_SAFE_INTEGER;
};

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
      ?.metadata as unknown as CISControlsAttributesMetadata[];
    const attrs = metadataArray?.[0];
    if (!attrs) continue;

    const requirementData = requirementsMap.get(id);
    if (!requirementData) continue;

    const frameworkName = attributeItem.attributes.framework;
    // Group by Section (the top-level CIS Control). Function, AssetType and
    // ImplementationGroups live inside the requirement so they show up on the
    // detail drawer.
    const categoryName = attrs.Section;
    const requirementName = attributeItem.attributes.name || "";
    const description = attributeItem.attributes.description;
    const status = requirementData.attributes.status || "";
    const checks = attributeItem.attributes.attributes.check_ids || [];

    const framework = findOrCreateFramework(frameworks, frameworkName);
    const category = findOrCreateCategory(framework.categories, categoryName);
    // Flat 2-level structure: control → safeguards (no intermediate level).
    const control = findOrCreateControl(category.controls, categoryName);

    const finalStatus: RequirementStatus = status as RequirementStatus;
    const requirement: Requirement = {
      name: requirementName ? `${id} - ${requirementName}` : id,
      description,
      status: finalStatus,
      check_ids: checks,
      ...getStatusCounters(finalStatus),
      function: attrs.Function ?? undefined,
      asset_type: attrs.AssetType ?? undefined,
      implementation_groups: attrs.ImplementationGroups ?? undefined,
    };

    control.requirements.push(requirement);
  }

  for (const framework of frameworks) {
    framework.categories.sort(
      (a, b) => sectionOrder(a.name) - sectionOrder(b.name),
    );
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
      // Control → safeguards (flat, no intermediate level).
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
