import type {
  FindingGroupRow,
  FindingResourceRow,
  FindingStatus,
  ProviderType,
  Severity,
} from "@/types";
import { FINDINGS_ROW_TYPE } from "@/types";

/**
 * API response shape for a finding group (JSON:API).
 * Each group represents a unique check_id with aggregated counts.
 *
 * Fields come from FindingGroupSerializer which aggregates
 * FindingGroupDailySummary rows by check_id.
 */
interface FindingGroupAttributes {
  check_id: string;
  check_title: string | null;
  check_description: string | null;
  severity: string;
  status: string; // "FAIL" | "PASS" | "MANUAL" (already uppercase)
  muted?: boolean;
  impacted_providers: string[];
  resources_total: number;
  resources_fail: number;
  pass_count: number;
  fail_count: number;
  manual_count?: number;
  pass_muted_count?: number;
  fail_muted_count?: number;
  manual_muted_count?: number;
  muted_count: number;
  new_count: number;
  changed_count: number;
  new_fail_count?: number;
  new_fail_muted_count?: number;
  new_pass_count?: number;
  new_pass_muted_count?: number;
  new_manual_count?: number;
  new_manual_muted_count?: number;
  changed_fail_count?: number;
  changed_fail_muted_count?: number;
  changed_pass_count?: number;
  changed_pass_muted_count?: number;
  changed_manual_count?: number;
  changed_manual_muted_count?: number;
  first_seen_at: string | null;
  last_seen_at: string | null;
  failing_since: string | null;
}

interface FindingGroupApiItem {
  type: "finding-groups";
  id: string;
  attributes: FindingGroupAttributes;
}

/**
 * Transforms the API response for finding groups into FindingGroupRow[].
 */
export function adaptFindingGroupsResponse(
  apiResponse: unknown,
): FindingGroupRow[] {
  if (
    !apiResponse ||
    typeof apiResponse !== "object" ||
    !("data" in apiResponse) ||
    !Array.isArray((apiResponse as { data: unknown }).data)
  ) {
    return [];
  }

  const data = (apiResponse as { data: FindingGroupApiItem[] }).data;
  return data.map((item) => ({
    id: item.id,
    rowType: FINDINGS_ROW_TYPE.GROUP,
    checkId: item.attributes.check_id,
    checkTitle: item.attributes.check_title || item.attributes.check_id,
    severity: item.attributes.severity as Severity,
    status: item.attributes.status as FindingStatus,
    muted:
      item.attributes.muted ??
      (item.attributes.muted_count > 0 &&
        (item.attributes.muted_count === item.attributes.resources_fail ||
          item.attributes.muted_count === item.attributes.resources_total)),
    resourcesTotal: item.attributes.resources_total,
    resourcesFail: item.attributes.resources_fail,
    passCount: item.attributes.pass_count,
    failCount: item.attributes.fail_count,
    manualCount: item.attributes.manual_count ?? 0,
    passMutedCount: item.attributes.pass_muted_count ?? 0,
    failMutedCount: item.attributes.fail_muted_count ?? 0,
    manualMutedCount: item.attributes.manual_muted_count ?? 0,
    newCount: item.attributes.new_count,
    changedCount: item.attributes.changed_count,
    newFailCount: item.attributes.new_fail_count ?? 0,
    newFailMutedCount: item.attributes.new_fail_muted_count ?? 0,
    newPassCount: item.attributes.new_pass_count ?? 0,
    newPassMutedCount: item.attributes.new_pass_muted_count ?? 0,
    newManualCount: item.attributes.new_manual_count ?? 0,
    newManualMutedCount: item.attributes.new_manual_muted_count ?? 0,
    changedFailCount: item.attributes.changed_fail_count ?? 0,
    changedFailMutedCount: item.attributes.changed_fail_muted_count ?? 0,
    changedPassCount: item.attributes.changed_pass_count ?? 0,
    changedPassMutedCount: item.attributes.changed_pass_muted_count ?? 0,
    changedManualCount: item.attributes.changed_manual_count ?? 0,
    changedManualMutedCount: item.attributes.changed_manual_muted_count ?? 0,
    mutedCount: item.attributes.muted_count,
    providers: (item.attributes.impacted_providers || []) as ProviderType[],
    updatedAt: item.attributes.last_seen_at || "",
  }));
}

/**
 * API response shape for a finding group resource (drill-down).
 * Endpoint: /finding-groups/{check_id}/resources
 *
 * Each item has nested `resource` and `provider` objects in attributes
 * (NOT JSON:API included — it's a custom serializer).
 */
interface ResourceInfo {
  uid: string;
  name: string;
  service: string;
  region: string;
  type: string;
  resource_group: string;
}

interface ProviderInfo {
  type: string;
  uid: string;
  alias: string;
}

interface FindingGroupResourceAttributes {
  finding_id: string;
  resource: ResourceInfo;
  provider: ProviderInfo;
  status: string;
  muted?: boolean;
  delta?: string | null;
  severity: string;
  first_seen_at: string | null;
  last_seen_at: string | null;
  muted_reason?: string | null;
}

interface FindingGroupResourceApiItem {
  type: "finding-group-resources";
  id: string;
  attributes: FindingGroupResourceAttributes;
}

/**
 * Transforms the API response for finding group resources (drill-down)
 * into FindingResourceRow[].
 */
export function adaptFindingGroupResourcesResponse(
  apiResponse: unknown,
  checkId: string,
): FindingResourceRow[] {
  if (
    !apiResponse ||
    typeof apiResponse !== "object" ||
    !("data" in apiResponse) ||
    !Array.isArray((apiResponse as { data: unknown }).data)
  ) {
    return [];
  }

  const data = (apiResponse as { data: FindingGroupResourceApiItem[] }).data;
  return data.map((item) => ({
    id: item.id,
    rowType: FINDINGS_ROW_TYPE.RESOURCE,
    findingId: item.attributes.finding_id || item.id,
    checkId,
    providerType: (item.attributes.provider?.type || "aws") as ProviderType,
    providerAlias: item.attributes.provider?.alias || "",
    providerUid: item.attributes.provider?.uid || "",
    resourceName: item.attributes.resource?.name || "-",
    resourceType: item.attributes.resource?.type || "-",
    resourceGroup: item.attributes.resource?.resource_group || "-",
    resourceUid: item.attributes.resource?.uid || "-",
    service: item.attributes.resource?.service || "-",
    region: item.attributes.resource?.region || "-",
    severity: (item.attributes.severity || "informational") as Severity,
    status: item.attributes.status,
    delta: item.attributes.delta || null,
    isMuted: item.attributes.muted ?? item.attributes.status === "MUTED",
    mutedReason: item.attributes.muted_reason || undefined,
    firstSeenAt: item.attributes.first_seen_at,
    lastSeenAt: item.attributes.last_seen_at,
  }));
}
