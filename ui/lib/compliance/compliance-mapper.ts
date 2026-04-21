import { createElement, ReactNode } from "react";

import { AWSWellArchitectedCustomDetails } from "@/components/compliance/compliance-custom-details/aws-well-architected-details";
import { C5CustomDetails } from "@/components/compliance/compliance-custom-details/c5-details";
import { CCCCustomDetails } from "@/components/compliance/compliance-custom-details/ccc-details";
import { CISCustomDetails } from "@/components/compliance/compliance-custom-details/cis-details";
import { CSACustomDetails } from "@/components/compliance/compliance-custom-details/csa-details";
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
  Framework,
  Requirement,
  RequirementsData,
  TopFailedResult,
} from "@/types/compliance";

import {
  mapComplianceData as mapAWSWellArchitectedComplianceData,
  toAccordionItems as toAWSWellArchitectedAccordionItems,
} from "./aws-well-architected";
import {
  mapComplianceData as mapC5ComplianceData,
  toAccordionItems as toC5AccordionItems,
} from "./c5";
import {
  mapComplianceData as mapCCCComplianceData,
  toAccordionItems as toCCCAccordionItems,
} from "./ccc";
import {
  mapComplianceData as mapCISComplianceData,
  toAccordionItems as toCISAccordionItems,
} from "./cis";
import { calculateCategoryHeatmapData, getTopFailedSections } from "./commons";
import {
  mapComplianceData as mapCSAComplianceData,
  toAccordionItems as toCSAAccordionItems,
} from "./csa";
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
  getTopFailedSections: (mappedData: Framework[]) => TopFailedResult;
  calculateCategoryHeatmapData: (complianceData: Framework[]) => CategoryData[];
  getDetailsComponent: (requirement: Requirement) => ReactNode;
}

const getDefaultMapper = (): ComplianceMapper => ({
  mapComplianceData: mapGenericComplianceData,
  toAccordionItems: toGenericAccordionItems,
  getTopFailedSections,
  calculateCategoryHeatmapData: (data: Framework[]) =>
    calculateCategoryHeatmapData(data),
  getDetailsComponent: (requirement: Requirement) =>
    createElement(GenericCustomDetails, { requirement }),
});

const getComplianceMappers = (): Record<string, ComplianceMapper> => ({
  C5: {
    mapComplianceData: mapC5ComplianceData,
    toAccordionItems: toC5AccordionItems,
    getTopFailedSections,
    calculateCategoryHeatmapData: (data: Framework[]) =>
      calculateCategoryHeatmapData(data),
    getDetailsComponent: (requirement: Requirement) =>
      createElement(C5CustomDetails, { requirement }),
  },
  ENS: {
    mapComplianceData: mapENSComplianceData,
    toAccordionItems: toENSAccordionItems,
    getTopFailedSections,
    calculateCategoryHeatmapData: (data: Framework[]) =>
      calculateCategoryHeatmapData(data),
    getDetailsComponent: (requirement: Requirement) =>
      createElement(ENSCustomDetails, { requirement }),
  },
  ISO27001: {
    mapComplianceData: mapISOComplianceData,
    toAccordionItems: toISOAccordionItems,
    getTopFailedSections,
    calculateCategoryHeatmapData: (data: Framework[]) =>
      calculateCategoryHeatmapData(data),
    getDetailsComponent: (requirement: Requirement) =>
      createElement(ISOCustomDetails, { requirement }),
  },
  CIS: {
    mapComplianceData: mapCISComplianceData,
    toAccordionItems: toCISAccordionItems,
    getTopFailedSections,
    calculateCategoryHeatmapData: (data: Framework[]) =>
      calculateCategoryHeatmapData(data),
    getDetailsComponent: (requirement: Requirement) =>
      createElement(CISCustomDetails, { requirement }),
  },
  "AWS-Well-Architected-Framework-Security-Pillar": {
    mapComplianceData: mapAWSWellArchitectedComplianceData,
    toAccordionItems: toAWSWellArchitectedAccordionItems,
    getTopFailedSections,
    calculateCategoryHeatmapData: (data: Framework[]) =>
      calculateCategoryHeatmapData(data),
    getDetailsComponent: (requirement: Requirement) =>
      createElement(AWSWellArchitectedCustomDetails, { requirement }),
  },
  "AWS-Well-Architected-Framework-Reliability-Pillar": {
    mapComplianceData: mapAWSWellArchitectedComplianceData,
    toAccordionItems: toAWSWellArchitectedAccordionItems,
    getTopFailedSections,
    calculateCategoryHeatmapData: (data: Framework[]) =>
      calculateCategoryHeatmapData(data),
    getDetailsComponent: (requirement: Requirement) =>
      createElement(AWSWellArchitectedCustomDetails, { requirement }),
  },
  "KISA-ISMS-P": {
    mapComplianceData: mapKISAComplianceData,
    toAccordionItems: toKISAAccordionItems,
    getTopFailedSections,
    calculateCategoryHeatmapData: (data: Framework[]) =>
      calculateCategoryHeatmapData(data),
    getDetailsComponent: (requirement: Requirement) =>
      createElement(KISACustomDetails, { requirement }),
  },
  "MITRE-ATTACK": {
    mapComplianceData: mapMITREComplianceData,
    toAccordionItems: toMITREAccordionItems,
    getTopFailedSections: getMITRETopFailedSections,
    calculateCategoryHeatmapData: calculateMITRECategoryHeatmapData,
    getDetailsComponent: (requirement: Requirement) =>
      createElement(MITRECustomDetails, { requirement }),
  },
  ProwlerThreatScore: {
    mapComplianceData: mapThetaComplianceData,
    toAccordionItems: toThetaAccordionItems,
    getTopFailedSections,
    calculateCategoryHeatmapData: (complianceData: Framework[]) =>
      calculateCategoryHeatmapData(complianceData),
    getDetailsComponent: (requirement: Requirement) =>
      createElement(ThreatCustomDetails, { requirement }),
  },
  CCC: {
    mapComplianceData: mapCCCComplianceData,
    toAccordionItems: toCCCAccordionItems,
    getTopFailedSections,
    calculateCategoryHeatmapData: (data: Framework[]) =>
      calculateCategoryHeatmapData(data),
    getDetailsComponent: (requirement: Requirement) =>
      createElement(CCCCustomDetails, { requirement }),
  },
  "CSA-CCM": {
    mapComplianceData: mapCSAComplianceData,
    toAccordionItems: toCSAAccordionItems,
    getTopFailedSections,
    calculateCategoryHeatmapData: (data: Framework[]) =>
      calculateCategoryHeatmapData(data),
    getDetailsComponent: (requirement: Requirement) =>
      createElement(CSACustomDetails, { requirement }),
  },
});

/**
 * Get the appropriate compliance mapper based on the framework name
 * @param framework - The framework name (e.g., "ENS", "ISO27001", "CIS")
 * @returns ComplianceMapper object with specific functions for the framework
 */
export const getComplianceMapper = (framework?: string): ComplianceMapper => {
  if (!framework) {
    return getDefaultMapper();
  }

  const complianceMappers = getComplianceMappers();
  return complianceMappers[framework] || getDefaultMapper();
};
