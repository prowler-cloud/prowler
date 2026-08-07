import { ClientAccordionContent } from "@/components/compliance/compliance-accordion/client-accordion-content";
import { ComplianceAccordionRequirementTitle } from "@/components/compliance/compliance-accordion/compliance-accordion-requeriment-title";
import { ComplianceAccordionTitle } from "@/components/compliance/compliance-accordion/compliance-accordion-title";
import { AccordionItemProps } from "@/components/ui/accordion/Accordion";
import { FindingStatus } from "@/components/ui/table/status-finding-badge";
import {
  AttributesData,
  CyberEssentialsAttributesMetadata,
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

// Display order for the five Cyber Essentials control themes in the accordion
// and any grouped chart. Mirrors the order declared in
// `prowler/compliance/cyber_essentials_3.3.json` so the UI always renders
// themes in the canonical reading order regardless of API response order.
export const CYBER_ESSENTIALS_THEME_ORDER: readonly string[] = [
  "Firewalls",
  "Secure Configuration",
  "Security Update Management",
  "User Access Control",
  "Malware Protection",
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
      ?.metadata as unknown as CyberEssentialsAttributesMetadata[];
    const attrs = metadataArray?.[0];
    if (!attrs) continue;

    const requirementData = requirementsMap.get(id);
    if (!requirementData) continue;

    const frameworkName = attributeItem.attributes.framework;
    // Group by Theme (top-level accordion section). The remaining attributes
    // live inside the requirement so they show up on the detail drawer.
    const categoryName = attrs.Theme;
    const requirementName = attributeItem.attributes.name || "";
    const description = attributeItem.attributes.description;
    const status = requirementData.attributes.status || "";
    const checks = attributeItem.attributes.attributes.check_ids || [];

    const framework = findOrCreateFramework(frameworks, frameworkName);
    const category = findOrCreateCategory(framework.categories, categoryName);
    // Flat 2-level structure: theme → requirements (no intermediate control).
    const control = findOrCreateControl(category.controls, categoryName);

    const finalStatus: RequirementStatus = status as RequirementStatus;
    const requirement: Requirement = {
      name: requirementName ? `${id} - ${requirementName}` : id,
      description,
      status: finalStatus,
      check_ids: checks,
      invalid_config: requirementData.attributes.invalid_config || false,
      ...getStatusCounters(finalStatus),
      theme: attrs.Theme,
      assessment_status: attrs.AssessmentStatus,
      cloud_applicability: attrs.CloudApplicability,
      remediation_procedure: attrs.RemediationProcedure,
      references: attrs.References,
    };

    control.requirements.push(requirement);
  }

  // Sort categories by canonical theme order so the framework always reads from
  // "Firewalls" down to "Malware Protection", regardless of map insertion order
  // driven by the API response.
  for (const framework of frameworks) {
    framework.categories.sort((a, b) => {
      const ia = CYBER_ESSENTIALS_THEME_ORDER.indexOf(a.name);
      const ib = CYBER_ESSENTIALS_THEME_ORDER.indexOf(b.name);
      // Unknown themes (defensive — shouldn't happen) sink to the bottom.
      const orderA = ia === -1 ? CYBER_ESSENTIALS_THEME_ORDER.length : ia;
      const orderB = ib === -1 ? CYBER_ESSENTIALS_THEME_ORDER.length : ib;
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
      // Theme → requirements (flat, no intermediate "control" level).
      items: category.controls.flatMap((control) =>
        control.requirements.map((requirement, reqIndex) => ({
          key: `${framework.name}-${category.name}-req-${reqIndex}`,
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
