import { PaginationLinks, RelationshipWrapper } from "./attack-paths";
import { ProviderType } from "./providers";

export interface ScannerArgs {
  only_logs?: boolean;
  excluded_checks?: string[];
  aws_retries_max_attempts?: number;
}

export const SCAN_TRIGGER = {
  SCHEDULED: "scheduled",
  MANUAL: "manual",
} as const;

export type ScanTrigger = (typeof SCAN_TRIGGER)[keyof typeof SCAN_TRIGGER];

export const SCAN_STATE = {
  AVAILABLE: "available",
  SCHEDULED: "scheduled",
  EXECUTING: "executing",
  COMPLETED: "completed",
  FAILED: "failed",
  CANCELLED: "cancelled",
} as const;

export type ScanState = (typeof SCAN_STATE)[keyof typeof SCAN_STATE];

export interface ScanAttributes {
  name: string;
  trigger: ScanTrigger;
  state: ScanState;
  unique_resource_count: number;
  progress: number;
  scanner_args: ScannerArgs | null;
  duration: number;
  started_at: string;
  inserted_at: string;
  completed_at: string;
  scheduled_at: string;
  next_scan_at: string;
}

export interface ScanRelationships {
  provider: RelationshipWrapper;
  task: RelationshipWrapper;
}

export interface ScanProviderInfo {
  provider: ProviderType;
  uid: string;
  alias: string;
}

export interface ScanProps {
  type: "scans";
  id: string;
  attributes: ScanAttributes;
  relationships: ScanRelationships;
  providerInfo?: ScanProviderInfo;
}

export interface ScanEntityProviderInfo {
  provider: ProviderType;
  alias?: string;
  uid?: string;
}

export interface ScanEntityAttributes {
  name?: string;
  completed_at: string;
}

export interface ScanEntity {
  id: string;
  providerInfo: ScanEntityProviderInfo;
  attributes: ScanEntityAttributes;
}

export interface ExpandedScanData extends ScanProps {
  providerInfo: ScanProviderInfo;
}

export interface IncludedResource {
  type: string;
  id: string;
  attributes: any;
  relationships?: any;
}

export interface ApiPagination {
  page: number;
  pages: number;
  count: number;
}

export interface ScansApiMeta {
  pagination: ApiPagination;
  version: string;
}

export interface ScansApiResponse {
  links: PaginationLinks;
  data: ScanProps[];
  included?: IncludedResource[];
  meta: ScansApiMeta;
}
