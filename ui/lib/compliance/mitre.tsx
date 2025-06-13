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
  RequirementsData,
  RequirementStatus,
} from "@/types/compliance";

import {
  calculateFrameworkCounters,
  createRequirementsMap,
  findOrCreateFramework,
} from "./commons";

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
      ?.metadata as unknown as MITREAttributesMetadata[];

    if (!metadataArray || metadataArray.length === 0) continue;

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
    const finalStatus: RequirementStatus = status as RequirementStatus;
    const requirement: Requirement = {
      name: requirementName,
      description: description,
      status: finalStatus,
      check_ids: checks,
      pass: finalStatus === "PASS" ? 1 : 0,
      fail: finalStatus === "FAIL" ? 1 : 0,
      manual: finalStatus === "MANUAL" ? 1 : 0,
      // MITRE specific fields
      technique_id: id,
      technique_name: techniqueName,
      tactics: tactics,
      subtechniques: subtechniques,
      platforms: platforms,
      technique_url: techniqueUrl,
      cloud_services: metadataArray.map((m) => {
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
      }),
    };

    // Add requirement directly to framework (store in a special property)
    (framework as any).requirements = (framework as any).requirements || [];
    (framework as any).requirements.push(requirement);
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
    const requirements = (framework as any).requirements || [];

    return requirements.map((requirement: Requirement, i: number) => {
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
): FailedSection[] => {
  const failedSectionMap = new Map();

  mappedData.forEach((framework) => {
    const requirements = (framework as any).requirements || [];

    requirements.forEach((requirement: Requirement) => {
      if (requirement.status === "FAIL") {
        const tactics = (requirement.tactics as string[]) || [];

        tactics.forEach((tactic) => {
          if (!failedSectionMap.has(tactic)) {
            failedSectionMap.set(tactic, { total: 0, types: {} });
          }

          const sectionData = failedSectionMap.get(tactic);
          sectionData.total += 1;

          const type = "Fails";
          sectionData.types[type] = (sectionData.types[type] || 0) + 1;
        });
      }
    });
  });

  // Convert in descending order and slice top 5
  return Array.from(failedSectionMap.entries())
    .map(([name, data]) => ({ name, ...data }))
    .sort((a, b) => b.total - a.total)
    .slice(0, 5); // Top 5
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
      const requirements = (framework as any).requirements || [];

      requirements.forEach((requirement: Requirement) => {
        const tactics = (requirement.tactics as string[]) || [];

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
