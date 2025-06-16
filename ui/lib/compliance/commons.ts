import React from "react";

import { AWSWellArchitectedCustomDetails } from "@/components/compliance/compliance-custom-details/aws-well-architected-details";
import { CISCustomDetails } from "@/components/compliance/compliance-custom-details/cis-details";
import { ENSCustomDetails } from "@/components/compliance/compliance-custom-details/ens-details";
import { GenericCustomDetails } from "@/components/compliance/compliance-custom-details/generic-details";
import { ISOCustomDetails } from "@/components/compliance/compliance-custom-details/iso-details";
import { KISACustomDetails } from "@/components/compliance/compliance-custom-details/kisa-details";
import { MITRECustomDetails } from "@/components/compliance/compliance-custom-details/mitre-details";
import { ThreatCustomDetails } from "@/components/compliance/compliance-custom-details/threat-details";
import { AccordionItemProps } from "@/components/ui/accordion/Accordion";
import {
  AttributesData,
  CategoryData,
  FailedSection,
  Framework,
  Requirement,
  RequirementsData,
} from "@/types/compliance";

import {
  mapComplianceData as mapAWSWellArchitectedComplianceData,
  toAccordionItems as toAWSWellArchitectedAccordionItems,
} from "./aws-well-architected";
import {
  mapComplianceData as mapCISComplianceData,
  toAccordionItems as toCISAccordionItems,
} from "./cis";
import {
  mapComplianceData as mapENSComplianceData,
  toAccordionItems as toENSAccordionItems,
} from "./ens";
import {
  mapComplianceData as mapGenericComplianceData,
  toAccordionItems as toGenericAccordionItems,
} from "./generic";
import {
  mapComplianceData as mapISOComplianceData,
  toAccordionItems as toISOAccordionItems,
} from "./iso";
import {
  mapComplianceData as mapKISAComplianceData,
  toAccordionItems as toKISAAccordionItems,
} from "./kisa";
import {
  calculateCategoryHeatmapData as calculateMITRECategoryHeatmapData,
  getTopFailedSections as getMITRETopFailedSections,
  mapComplianceData as mapMITREComplianceData,
  toAccordionItems as toMITREAccordionItems,
} from "./mitre";
import {
  mapComplianceData as mapThetaComplianceData,
  toAccordionItems as toThetaAccordionItems,
} from "./threat";

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
  calculateCategoryHeatmapData: (complianceData: Framework[]) => CategoryData[];
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
    calculateCategoryHeatmapData: (data: Framework[]) =>
      calculateCategoryHeatmapData(data),
    getDetailsComponent: (requirement: Requirement) =>
      React.createElement(ENSCustomDetails, { requirement }),
  },
  ISO27001: {
    mapComplianceData: mapISOComplianceData,
    toAccordionItems: toISOAccordionItems,
    getTopFailedSections,
    calculateCategoryHeatmapData: (data: Framework[]) =>
      calculateCategoryHeatmapData(data),
    getDetailsComponent: (requirement: Requirement) =>
      React.createElement(ISOCustomDetails, { requirement }),
  },
  CIS: {
    mapComplianceData: mapCISComplianceData,
    toAccordionItems: toCISAccordionItems,
    getTopFailedSections,
    calculateCategoryHeatmapData: (data: Framework[]) =>
      calculateCategoryHeatmapData(data),
    getDetailsComponent: (requirement: Requirement) =>
      React.createElement(CISCustomDetails, { requirement }),
  },
  "AWS-Well-Architected-Framework-Security-Pillar": {
    mapComplianceData: mapAWSWellArchitectedComplianceData,
    toAccordionItems: toAWSWellArchitectedAccordionItems,
    getTopFailedSections,
    calculateCategoryHeatmapData: (data: Framework[]) =>
      calculateCategoryHeatmapData(data),
    getDetailsComponent: (requirement: Requirement) =>
      React.createElement(AWSWellArchitectedCustomDetails, { requirement }),
  },
  "AWS-Well-Architected-Framework-Reliability-Pillar": {
    mapComplianceData: mapAWSWellArchitectedComplianceData,
    toAccordionItems: toAWSWellArchitectedAccordionItems,
    getTopFailedSections,
    calculateCategoryHeatmapData: (data: Framework[]) =>
      calculateCategoryHeatmapData(data),
    getDetailsComponent: (requirement: Requirement) =>
      React.createElement(AWSWellArchitectedCustomDetails, { requirement }),
  },
  "KISA-ISMS-P": {
    mapComplianceData: mapKISAComplianceData,
    toAccordionItems: toKISAAccordionItems,
    getTopFailedSections,
    calculateCategoryHeatmapData: (data: Framework[]) =>
      calculateCategoryHeatmapData(data),
    getDetailsComponent: (requirement: Requirement) =>
      React.createElement(KISACustomDetails, { requirement }),
  },
  "MITRE-ATTACK": {
    mapComplianceData: mapMITREComplianceData,
    toAccordionItems: toMITREAccordionItems,
    getTopFailedSections: getMITRETopFailedSections,
    calculateCategoryHeatmapData: calculateMITRECategoryHeatmapData,
    getDetailsComponent: (requirement: Requirement) =>
      React.createElement(MITRECustomDetails, { requirement }),
  },
  ProwlerThreatScore: {
    mapComplianceData: mapThetaComplianceData,
    toAccordionItems: toThetaAccordionItems,
    getTopFailedSections,
    calculateCategoryHeatmapData: (complianceData: Framework[]) =>
      calculateCategoryHeatmapData(complianceData),
    getDetailsComponent: (requirement: Requirement) =>
      React.createElement(ThreatCustomDetails, { requirement }),
  },
};

// Default mapper (fallback to generic for maximum compatibility)
const defaultMapper: ComplianceMapper = {
  mapComplianceData: mapGenericComplianceData,
  toAccordionItems: toGenericAccordionItems,
  getTopFailedSections,
  calculateCategoryHeatmapData: (data: Framework[]) =>
    calculateCategoryHeatmapData(data),
  getDetailsComponent: (requirement: Requirement) =>
    React.createElement(GenericCustomDetails, { requirement }),
};

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
