import { AccordionItemProps } from "@/components/ui/accordion/Accordion";
import {
  AttributesData,
  FailedSection,
  Framework,
  RequirementsData,
} from "@/types/compliance";

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
  ) => Framework[];
  toAccordionItems: (
    data: Framework[],
    scanId: string | undefined,
  ) => AccordionItemProps[];
  getTopFailedSections: (mappedData: Framework[]) => FailedSection[];
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
  },
  ISO27001: {
    mapComplianceData: mapISOComplianceData,
    toAccordionItems: toISOAccordionItems,
    getTopFailedSections,
  },
};

// Default mapper (fallback to ENS for backward compatibility)
const defaultMapper: ComplianceMapper = complianceMappers.ENS;

/**
 * Get the appropriate compliance mapper based on the framework name
 * @param framework - The framework name (e.g., "ENS", "ISO27001")
 * @returns ComplianceMapper object with specific functions for the framework
 */
export const getComplianceMapper = (framework?: string): ComplianceMapper => {
  if (!framework) {
    return defaultMapper;
  }

  return complianceMappers[framework] || defaultMapper;
};
