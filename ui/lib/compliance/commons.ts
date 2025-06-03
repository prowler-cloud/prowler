import { CISCustomDetails } from "@/components/compliance/compliance-custom-details/cis-details";
import { ENSCustomDetails } from "@/components/compliance/compliance-custom-details/ens-details";
import { ISOCustomDetails } from "@/components/compliance/compliance-custom-details/iso-details";
import { AccordionItemProps } from "@/components/ui/accordion/Accordion";
import {
  AttributesData,
  CategoryData,
  FailedSection,
  Framework,
  RegionData,
  Requirement,
  RequirementsData,
} from "@/types/compliance";
import React from "react";

import {
  mapComplianceData as mapCISComplianceData,
  toAccordionItems as toCISAccordionItems,
} from "./cis";
import {
  mapComplianceData as mapENSComplianceData,
  toAccordionItems as toENSAccordionItems,
} from "./ens";
import {
  mapComplianceData as mapISOComplianceData,
  toAccordionItems as toISOAccordionItems,
} from "./iso";

export interface ComplianceMapper {
  mapComplianceData: (
    attributesData: AttributesData,
    requirementsData: RequirementsData,
    filter?: string,
  ) => Framework[];
  toAccordionItems: (
    data: Framework[],
    scanId: string | undefined,
  ) => AccordionItemProps[];
  getTopFailedSections: (mappedData: Framework[]) => FailedSection[];
  getDetailsComponent: (requirement: Requirement) => React.ReactNode;
}

// Common function for getting top failed sections
export const getTopFailedSections = (
  mappedData: Framework[],
): FailedSection[] => {
  const failedSectionMap = new Map();

  mappedData.forEach((framework) => {
    framework.categories.forEach((category) => {
      category.controls.forEach((control) => {
        control.requirements.forEach((requirement) => {
          if (requirement.status === "FAIL") {
            const sectionName = category.name;

            if (!failedSectionMap.has(sectionName)) {
              failedSectionMap.set(sectionName, { total: 0, types: {} });
            }

            const sectionData = failedSectionMap.get(sectionName);
            sectionData.total += 1;

            const type = requirement.type || "Fails";

            sectionData.types[type as string] =
              (sectionData.types[type as string] || 0) + 1;
          }
        });
      });
    });
  });

  // Convert in descending order and slice top 5
  return Array.from(failedSectionMap.entries())
    .map(([name, data]) => ({ name, ...data }))
    .sort((a, b) => b.total - a.total)
    .slice(0, 5); // Top 5
};

// Registry of compliance mappers
const complianceMappers: Record<string, ComplianceMapper> = {
  ENS: {
    mapComplianceData: mapENSComplianceData,
    toAccordionItems: toENSAccordionItems,
    getTopFailedSections,
    getDetailsComponent: (requirement: Requirement) =>
      React.createElement(ENSCustomDetails, { requirement }),
  },
  ISO27001: {
    mapComplianceData: mapISOComplianceData,
    toAccordionItems: toISOAccordionItems,
    getTopFailedSections,
    getDetailsComponent: (requirement: Requirement) =>
      React.createElement(ISOCustomDetails, { requirement }),
  },
  CIS: {
    mapComplianceData: mapCISComplianceData,
    toAccordionItems: toCISAccordionItems,
    getTopFailedSections,
    getDetailsComponent: (requirement: Requirement) =>
      React.createElement(CISCustomDetails, { requirement }),
  },
};

// Default mapper (fallback to ENS for backward compatibility)
const defaultMapper: ComplianceMapper = complianceMappers.ENS;

/**
 * Get the appropriate compliance mapper based on the framework name
 * @param framework - The framework name (e.g., "ENS", "ISO27001", "CIS")
 * @returns ComplianceMapper object with specific functions for the framework
 */
export const getComplianceMapper = (framework?: string): ComplianceMapper => {
  if (!framework) {
    return defaultMapper;
  }

  return complianceMappers[framework] || defaultMapper;
};

export const calculateRegionHeatmapData = async (
  complianceId: string,
  scanId: string,
  uniqueRegions: string[],
  attributesData: AttributesData,
  mapper: ComplianceMapper,
): Promise<RegionData[]> => {
  if (!complianceId || !scanId || !uniqueRegions?.length) {
    return [];
  }

  try {
    const { getComplianceRequirements } = await import("@/actions/compliances");

    // Get data for each region in parallel
    const regionPromises = uniqueRegions.map(async (region) => {
      try {
        // Only need to fetch requirements data per region
        const regionRequirementsData = await getComplianceRequirements({
          complianceId,
          scanId,
          region, // Filter by specific region
        });

        // Map the data using the provided mapper
        const mappedData = mapper.mapComplianceData(
          attributesData,
          regionRequirementsData,
        );

        // Calculate totals for this region
        const regionTotals = mappedData.reduce(
          (acc, framework) => ({
            pass: acc.pass + framework.pass,
            fail: acc.fail + framework.fail,
            manual: acc.manual + framework.manual,
          }),
          { pass: 0, fail: 0, manual: 0 },
        );

        const totalRequirements =
          regionTotals.pass + regionTotals.fail + regionTotals.manual;
        const failurePercentage =
          totalRequirements > 0
            ? Math.round((regionTotals.fail / totalRequirements) * 100)
            : 0;

        return {
          name: region,
          failurePercentage,
          totalRequirements,
          failedRequirements: regionTotals.fail,
        };
      } catch (error) {
        console.error(`Error fetching data for region ${region}:`, error);
        return {
          name: region,
          failurePercentage: 0,
          totalRequirements: 0,
          failedRequirements: 0,
        };
      }
    });

    const regionData = await Promise.all(regionPromises);

    // Filter, sort and limit to top 9 regions for 3x3 grid
    const filteredData = regionData
      .filter((region) => region.totalRequirements > 0)
      .sort((a, b) => b.failurePercentage - a.failurePercentage)
      .slice(0, 9);

    return filteredData;
  } catch (error) {
    console.error("Error calculating region heatmap data:", error);
    return [];
  }
};

export const calculateCategoryHeatmapData = (
  complianceData: Framework[],
): CategoryData[] => {
  if (!complianceData?.length) {
    return [];
  }

  try {
    const categoryMap = new Map<
      string,
      { pass: number; fail: number; manual: number }
    >();

    // Aggregate data by category
    complianceData.forEach((framework) => {
      framework.categories.forEach((category) => {
        const existing = categoryMap.get(category.name) || {
          pass: 0,
          fail: 0,
          manual: 0,
        };
        categoryMap.set(category.name, {
          pass: existing.pass + category.pass,
          fail: existing.fail + category.fail,
          manual: existing.manual + category.manual,
        });
      });
    });

    const categoryData: CategoryData[] = Array.from(categoryMap.entries()).map(
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
      .slice(0, 9); // Show top 9 categories

    return filteredData;
  } catch (error) {
    console.error("Error calculating category heatmap data:", error);
    return [];
  }
};
