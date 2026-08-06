import { StaticImageData } from "next/image";

import type {
  ComplianceOverviewData,
  RequirementsData,
} from "@/types/compliance";
import type { TaskAttributes } from "@/types/tasks";

export const COMPLIANCE_OVERVIEW_RESOURCE_TYPE = {
  TASK: "tasks",
} as const;

/**
 * Raw API response from /compliance-overviews endpoint
 */
export interface ComplianceOverviewsResponse {
  data: ComplianceOverviewData[];
  meta?: {
    pagination?: {
      page: number;
      pages: number;
      count: number;
    };
  };
}

export interface ComplianceOverviewTaskResource {
  id: string;
  type: typeof COMPLIANCE_OVERVIEW_RESOURCE_TYPE.TASK;
  attributes?: TaskAttributes;
}

export interface ComplianceOverviewTaskResponse {
  data: ComplianceOverviewTaskResource;
}

export type ComplianceOverviewApiResponse =
  | ComplianceOverviewsResponse
  | ComplianceOverviewTaskResponse;

export type ComplianceRequirementsApiResponse =
  | RequirementsData
  | ComplianceOverviewTaskResponse;

/**
 * Enriched compliance overview with computed fields
 */
export interface EnrichedComplianceOverview {
  id: string;
  framework: string;
  version: string;
  requirements_passed: number;
  requirements_failed: number;
  requirements_manual: number;
  total_requirements: number;
  score: number;
  label: string;
  icon: string | StaticImageData | undefined;
}
