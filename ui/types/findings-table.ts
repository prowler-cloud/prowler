import { FindingStatus, Severity } from "./components";
import { ProviderType } from "./providers";

export const FINDINGS_ROW_TYPE = {
  GROUP: "group",
  RESOURCE: "resource",
} as const;

export type FindingsRowType =
  (typeof FINDINGS_ROW_TYPE)[keyof typeof FINDINGS_ROW_TYPE];

export interface FindingGroupRow {
  id: string;
  rowType: typeof FINDINGS_ROW_TYPE.GROUP;
  checkId: string;
  checkTitle: string;
  severity: Severity;
  status: FindingStatus;
  resourcesTotal: number;
  resourcesFail: number;
  newCount: number;
  changedCount: number;
  mutedCount: number;
  providers: ProviderType[];
  updatedAt: string;
}

export interface FindingResourceRow {
  id: string;
  rowType: typeof FINDINGS_ROW_TYPE.RESOURCE;
  findingId: string;
  checkId: string;
  providerType: ProviderType;
  providerAlias: string;
  providerUid: string;
  resourceName: string;
  resourceType: string;
  resourceGroup: string;
  resourceUid: string;
  service: string;
  region: string;
  severity: Severity;
  status: string;
  delta?: string | null;
  isMuted: boolean;
  mutedReason?: string;
  firstSeenAt: string | null;
  lastSeenAt: string | null;
}

export type FindingsTableRow = FindingGroupRow | FindingResourceRow;

export function isFindingGroupRow(
  row: FindingsTableRow,
): row is FindingGroupRow {
  return row.rowType === FINDINGS_ROW_TYPE.GROUP;
}

export function isFindingResourceRow(
  row: FindingsTableRow,
): row is FindingResourceRow {
  return row.rowType === FINDINGS_ROW_TYPE.RESOURCE;
}
