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
import { calculateCategoryHeatmapData, getTopFailedSections } from "./commons";
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

export const complianceMappers: Record<string, ComplianceMapper> = {
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
