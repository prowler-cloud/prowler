import { ClientAccordionContent } from "@/components/compliance/compliance-accordion/client-accordion-content";
import { ComplianceAccordionRequirementTitle } from "@/components/compliance/compliance-accordion/compliance-accordion-requeriment-title";
import { AccordionItemProps } from "@/components/ui/accordion/Accordion";
import { FindingStatus } from "@/components/ui/table/status-finding-badge";
import {
  AttributesData,
  CategoryData,
  FailedSection,
  Framework,
  MITREAttributesMetadata,
  Requirement,
  REQUIREMENT_STATUS,
  RequirementsData,
  RequirementStatus,
  TOP_FAILED_DATA_TYPE,
  TopFailedResult,
} from "@/types/compliance";

import {
  calculateFrameworkCounters,
  createRequirementsMap,
  findOrCreateFramework,
} from "./commons";

// Type for the internal map used in getTopFailedSections
interface FailedSectionData {
  total: number;
  types: Record<string, number>;
}

export const mapComplianceData = (
  attributesData: AttributesData,
  requirementsData: RequirementsData,
): Framework[] => {
  const attributes = attributesData?.data || [];
  const requirementsMap = createRequirementsMap(requirementsData);

  const frameworks: Framework[] = [];

  // Process ALL attributes to ensure consistent counters for charts
  for (const attributeItem of attributes) {
    const id = attributeItem.id;
    const metadataArray = attributeItem.attributes?.attributes
      ?.metadata as unknown as MITREAttributesMetadata[];

    // Get corresponding requirement data
    const requirementData = requirementsMap.get(id);
    if (!requirementData) continue;

    const frameworkName = attributeItem.attributes.framework;
    const techniqueName = attributeItem.attributes.name || id;
    const description = attributeItem.attributes.description;
    const status = requirementData.attributes.status || "";
    const checks = attributeItem.attributes.attributes.check_ids || [];
    const techniqueDetails =
      attributeItem.attributes.attributes.technique_details;
    const tactics = techniqueDetails?.tactics || [];
    const subtechniques = techniqueDetails?.subtechniques || [];
    const platforms = techniqueDetails?.platforms || [];
    const techniqueUrl = techniqueDetails?.technique_url || "";
    const requirementName = `${id} - ${techniqueName}`;

    // Find or create framework using common helper
    const framework = findOrCreateFramework(frameworks, frameworkName);

    // Create requirement directly (flat structure - no categories)
    // Include ALL requirements, even those without metadata (for accurate chart counts)
    const finalStatus: RequirementStatus = status as RequirementStatus;
    const requirement: Requirement = {
      name: requirementName,
      description: description,
      status: finalStatus,
      check_ids: checks,
      pass: finalStatus === REQUIREMENT_STATUS.PASS ? 1 : 0,
      fail: finalStatus === REQUIREMENT_STATUS.FAIL ? 1 : 0,
      manual: finalStatus === REQUIREMENT_STATUS.MANUAL ? 1 : 0,
      // MITRE specific fields
      technique_id: id,
      technique_name: techniqueName,
      tactics: tactics,
      subtechniques: subtechniques,
      platforms: platforms,
      technique_url: techniqueUrl,
      // Mark items without metadata so accordion can filter them out
      hasMetadata: !!(metadataArray && metadataArray.length > 0),
      cloud_services:
        metadataArray?.map((m) => {
          // Dynamically find the service field (AWSService, GCPService, AzureService, etc.)
          const serviceKey = Object.keys(m).find((key) =>
            key.toLowerCase().includes("service"),
          );
          const serviceName = serviceKey ? m[serviceKey] : "Unknown Service";

          return {
            service: serviceName,
            category: m.Category,
            value: m.Value,
            comment: m.Comment,
          };
        }) || [],
    };

    // Add requirement directly to framework (flat structure - no categories)
    framework.requirements = framework.requirements ?? [];
    framework.requirements.push(requirement);
  }

  // Calculate counters using common helper (works with flat structure)
  calculateFrameworkCounters(frameworks);

  return frameworks;
};

export const toAccordionItems = (
  data: Framework[],
  scanId: string | undefined,
): AccordionItemProps[] => {
  return data.flatMap((framework) => {
    const requirements = framework.requirements ?? [];

    // Filter out requirements without metadata (can't be displayed in accordion)
    const displayableRequirements = requirements.filter(
      (requirement) => requirement.hasMetadata !== false,
    );

    return displayableRequirements.map((requirement, i) => {
      const itemKey = `${framework.name}-req-${i}`;

      return {
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
            scanId={scanId || ""}
            framework={framework.name}
            disableFindings={
              requirement.check_ids.length === 0 && requirement.manual === 0
            }
          />
        ),
        items: [],
      };
    });
  });
};

// Custom function for MITRE to get top failed sections grouped by tactics
export const getTopFailedSections = (
  mappedData: Framework[],
): TopFailedResult => {
  const failedSectionMap = new Map<string, FailedSectionData>();

  mappedData.forEach((framework) => {
    const requirements = framework.requirements ?? [];

    requirements.forEach((requirement) => {
      if (requirement.status === REQUIREMENT_STATUS.FAIL) {
        const tactics = Array.isArray(requirement.tactics)
          ? (requirement.tactics as string[])
          : [];

        tactics.forEach((tactic) => {
          if (!failedSectionMap.has(tactic)) {
            failedSectionMap.set(tactic, { total: 0, types: {} });
          }

          const sectionData = failedSectionMap.get(tactic)!;
          sectionData.total += 1;

          const type = "Fails";
          sectionData.types[type] = (sectionData.types[type] || 0) + 1;
        });
      }
    });
  });

  // Convert in descending order and slice top 5
  return {
    items: Array.from(failedSectionMap.entries())
      .map(([name, data]): FailedSection => ({ name, ...data }))
      .sort((a, b) => b.total - a.total)
      .slice(0, 5),
    type: TOP_FAILED_DATA_TYPE.SECTIONS,
  };
};

// Custom function for MITRE to calculate category heatmap data grouped by tactics
export const calculateCategoryHeatmapData = (
  complianceData: Framework[],
): CategoryData[] => {
  if (!complianceData?.length) {
    return [];
  }

  try {
    const tacticMap = new Map<
      string,
      { pass: number; fail: number; manual: number }
    >();

    // Aggregate data by tactics
    complianceData.forEach((framework) => {
      const requirements = framework.requirements ?? [];

      requirements.forEach((requirement) => {
        const tactics = Array.isArray(requirement.tactics)
          ? (requirement.tactics as string[])
          : [];

        tactics.forEach((tactic) => {
          const existing = tacticMap.get(tactic) || {
            pass: 0,
            fail: 0,
            manual: 0,
          };

          tacticMap.set(tactic, {
            pass: existing.pass + requirement.pass,
            fail: existing.fail + requirement.fail,
            manual: existing.manual + requirement.manual,
          });
        });
      });
    });

    const categoryData: CategoryData[] = Array.from(tacticMap.entries()).map(
      ([name, stats]) => {
        const totalRequirements = stats.pass + stats.fail + stats.manual;
        const failurePercentage =
          totalRequirements > 0
            ? Math.round((stats.fail / totalRequirements) * 100)
            : 0;

        return {
          name,
          failurePercentage,
          totalRequirements,
          failedRequirements: stats.fail,
        };
      },
    );

    const filteredData = categoryData
      .filter((category) => category.totalRequirements > 0)
      .sort((a, b) => b.failurePercentage - a.failurePercentage)
      .slice(0, 9); // Show top 9 tactics

    return filteredData;
  } catch (error) {
    console.error("Error calculating MITRE category heatmap data:", error);
    return [];
  }
};
