import type { ProviderType } from "./providers";

/** Mirrors `PARTIAL_SCAN_MAX_RESOURCES` in the Cloud API. */
export const PARTIAL_SCAN_MAX_RESOURCES = 10;

/** One resource to re-check. Prowler Cloud only. */
export interface PartialScanTarget {
  /** Provider UUID. Resolved from `providerUid` + `providerType` when absent. */
  providerId?: string;
  providerUid: string;
  providerType: ProviderType;
  providerAlias?: string;
  resourceUid: string;
  resourceName: string;
}
