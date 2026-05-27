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
  IMPORTED: "imported",
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

export const SCAN_JOBS_TAB = {
  ACTIVE: "active",
  COMPLETED: "completed",
  SCHEDULED: "scheduled",
} as const;

export type ScanJobsTab = (typeof SCAN_JOBS_TAB)[keyof typeof SCAN_JOBS_TAB];

export const DEFAULT_SCAN_JOBS_TAB: ScanJobsTab = SCAN_JOBS_TAB.ACTIVE;

export const SCAN_TAB_LABELS: Record<ScanJobsTab, string> = {
  [SCAN_JOBS_TAB.ACTIVE]: "In Progress",
  [SCAN_JOBS_TAB.COMPLETED]: "Completed",
  [SCAN_JOBS_TAB.SCHEDULED]: "Scheduled",
};

export interface ScanFindingsSummary {
  fail: number;
  pass: number;
  failNew?: number;
  passNew?: number;
}

export interface ScanAttributes {
  name: string;
  trigger: ScanTrigger;
  state: ScanState;
  unique_resource_count: number;
  progress: number;
  scanner_args: ScannerArgs | null;
  duration: number | null;
  started_at: string | null;
  inserted_at: string;
  completed_at: string | null;
  scheduled_at: string | null;
  next_scan_at: string | null;
}

export interface ScanRelationships {
  provider: RelationshipWrapper;
  task: RelationshipWrapper;
}

export interface ScanResultProviderInfo {
  provider: ProviderType;
  uid: string;
  alias: string;
}

export interface ScanProviderInfo {
  providerId: string;
  alias: string;
  providerType: string;
  uid: string;
  connected: boolean;
}

export interface ScanProps {
  type: "scans";
  id: string;
  attributes: ScanAttributes;
  relationships: ScanRelationships;
  providerInfo?: ScanResultProviderInfo;
}

export interface ScanEntityProviderInfo {
  provider: ProviderType;
  alias?: string;
  uid?: string;
}

export interface ScanEntityAttributes {
  name?: string;
  completed_at: string | null;
}

export interface ScanEntity {
  id: string;
  providerInfo: ScanEntityProviderInfo;
  attributes: ScanEntityAttributes;
}

export interface ExpandedScanData extends ScanProps {
  providerInfo: ScanResultProviderInfo;
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
