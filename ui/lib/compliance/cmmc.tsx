import { ClientAccordionContent } from "@/components/compliance/compliance-accordion/client-accordion-content";
import { ComplianceAccordionRequirementTitle } from "@/components/compliance/compliance-accordion/compliance-accordion-requeriment-title";
import { ComplianceAccordionTitle } from "@/components/compliance/compliance-accordion/compliance-accordion-title";
import { AccordionItemProps } from "@/components/shadcn/accordion/Accordion";
import { FindingStatus } from "@/components/shadcn/table/status-finding-badge";
import {
  AttributesData,
  CMMCAttributesMetadata,
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

// Canonical NIST SP 800-171 family order for the 14 CMMC domains, so the
// accordion always reads in the same order regardless of the API response.
export const CMMC_DOMAIN_ORDER: readonly string[] = [
  "Access Control",
  "Awareness and Training",
  "Audit and Accountability",
  "Configuration Management",
  "Identification and Authentication",
  "Incident Response",
  "Maintenance",
  "Media Protection",
  "Personnel Security",
  "Physical Protection",
  "Risk Assessment",
  "Security Assessment",
  "System and Communications Protection",
  "System and Information Integrity",
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
      ?.metadata as unknown as CMMCAttributesMetadata[];
    const attrs = metadataArray?.[0];
    if (!attrs) continue;

    const requirementData = requirementsMap.get(id);
    if (!requirementData) continue;

    const frameworkName = attributeItem.attributes.framework;
    // Group by Domain. Level and SourceRequirement live inside the requirement
    // so they show up on the detail drawer.
    const categoryName = attrs.Domain;
    const requirementName = attributeItem.attributes.name || "";
    const description = attributeItem.attributes.description;
    const status = requirementData.attributes.status || "";
    const checks = attributeItem.attributes.attributes.check_ids || [];

    const framework = findOrCreateFramework(frameworks, frameworkName);
    const category = findOrCreateCategory(framework.categories, categoryName);
    // Flat 2-level structure: domain → requirements (no intermediate control).
    const control = findOrCreateControl(category.controls, categoryName);

    const finalStatus: RequirementStatus = status as RequirementStatus;
    const requirement: Requirement = {
      name: requirementName ? `${id} - ${requirementName}` : id,
      description,
      status: finalStatus,
      check_ids: checks,
      invalid_config: requirementData.attributes.invalid_config || false,
      ...getStatusCounters(finalStatus),
      domain: attrs.Domain,
      level: attrs.Level,
      source_requirement: attrs.SourceRequirement,
    };

    control.requirements.push(requirement);
  }

  // Sort domains by the canonical NIST 800-171 family order.
  for (const framework of frameworks) {
    framework.categories.sort((a, b) => {
      const ia = CMMC_DOMAIN_ORDER.indexOf(a.name);
      const ib = CMMC_DOMAIN_ORDER.indexOf(b.name);
      const orderA = ia === -1 ? CMMC_DOMAIN_ORDER.length : ia;
      const orderB = ib === -1 ? CMMC_DOMAIN_ORDER.length : ib;
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
      // Domain → requirements (flat, no intermediate "control" level).
      // Keys are derived from the requirement name (which starts with the
      // unique CMMC id, e.g. "AC.L1-b.1.i") instead of the array index, so
      // expanded state stays attached to the right requirement even if the
      // list is reordered or filtered.
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
