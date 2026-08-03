import type { WatchlistScope } from "@/types/compliance-watchlist";

export const FINDING_COMPLIANCE_FRAMEWORK_TYPE =
  "finding-compliance-frameworks" as const;

export interface FindingComplianceFrameworkAttributes {
  compliance_id: string;
  provider_type: string;
  scope: string;
  framework: string;
  name: string;
  version: string;
  in_watchlist: boolean;
}

export interface FindingComplianceFrameworkResource {
  type: string;
  id: string;
  attributes: FindingComplianceFrameworkAttributes;
}

export interface FindingComplianceFrameworksResponse {
  data: FindingComplianceFrameworkResource[];
}

/** One framework the finding's check belongs to. `complianceId` is the
 *  navigable identity; `framework` is only for the label and the logo. */
export interface FindingComplianceFramework {
  id: string;
  complianceId: string;
  providerType: string;
  scope: WatchlistScope;
  framework: string;
  name: string;
  version: string;
  inWatchlist: boolean;
}

export interface FindingComplianceFrameworksResult {
  frameworks: FindingComplianceFramework[];
  /** The endpoint could not answer — it is Cloud-only, so this is the normal
   *  case on a self-hosted install. Distinct from an empty watchlist, which is
   *  a real answer, so the caller can fall back instead of hiding the strip. */
  unavailable: boolean;
}
