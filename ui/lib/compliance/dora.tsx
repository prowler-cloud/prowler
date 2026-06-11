import { ClientAccordionContent } from "@/components/compliance/compliance-accordion/client-accordion-content";
import { ComplianceAccordionRequirementTitle } from "@/components/compliance/compliance-accordion/compliance-accordion-requeriment-title";
import { ComplianceAccordionTitle } from "@/components/compliance/compliance-accordion/compliance-accordion-title";
import { AccordionItemProps } from "@/components/shadcn/accordion/Accordion";
import { FindingStatus } from "@/components/shadcn/table/status-finding-badge";
import {
  AttributesData,
  DORAAttributesMetadata,
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

// Display order for DORA pillars in the accordion and any grouped chart. The
// regulation arranges them in this exact order (Articles 5-14, 17-19, 24-25,
// 28+30, 45) — preserving it here means the UI always renders pillars in the
// "logical" reading order regardless of how the API returns them.
export const DORA_PILLAR_ORDER: readonly string[] = [
  "ICT Risk Management",
  "ICT-Related Incident Reporting",
  "Digital Operational Resilience Testing",
  "ICT Third-Party Risk Management",
  "Information Sharing",
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
      ?.metadata as unknown as DORAAttributesMetadata[];
    const attrs = metadataArray?.[0];
    if (!attrs) continue;

    const requirementData = requirementsMap.get(id);
    if (!requirementData) continue;

    const frameworkName = attributeItem.attributes.framework;
    // Group by Pillar (top-level accordion section). Article + ArticleTitle
    // live inside the requirement so they show up on the detail drawer.
    const categoryName = attrs.Pillar;
    const requirementName = attributeItem.attributes.name || "";
    const description = attributeItem.attributes.description;
    const status = requirementData.attributes.status || "";
    const checks = attributeItem.attributes.attributes.check_ids || [];

    const framework = findOrCreateFramework(frameworks, frameworkName);
    const category = findOrCreateCategory(framework.categories, categoryName);
    // Flat 2-level structure: pillar → requirements (no intermediate control).
    const control = findOrCreateControl(category.controls, categoryName);

    const finalStatus: RequirementStatus = status as RequirementStatus;
    const requirement: Requirement = {
      name: requirementName ? `${id} - ${requirementName}` : id,
      description,
      status: finalStatus,
      check_ids: checks,
      ...getStatusCounters(finalStatus),
      pillar: attrs.Pillar,
      article: attrs.Article,
      article_title: attrs.ArticleTitle,
    };

    control.requirements.push(requirement);
  }

  // Sort categories by canonical pillar order so DORA always reads from "ICT
  // Risk Management" down to "Information Sharing", regardless of map insertion
  // order driven by the API response.
  for (const framework of frameworks) {
    framework.categories.sort((a, b) => {
      const ia = DORA_PILLAR_ORDER.indexOf(a.name);
      const ib = DORA_PILLAR_ORDER.indexOf(b.name);
      // Unknown pillars (defensive — shouldn't happen) sink to the bottom.
      const orderA = ia === -1 ? DORA_PILLAR_ORDER.length : ia;
      const orderB = ib === -1 ? DORA_PILLAR_ORDER.length : ib;
      return orderA - orderB;
    });
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
      // Pillar → requirements (flat, no intermediate "control" level).
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
