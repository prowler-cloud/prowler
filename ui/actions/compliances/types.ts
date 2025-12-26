import { StaticImageData } from "next/image";

import { ComplianceOverviewData } from "@/types/compliance";

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
