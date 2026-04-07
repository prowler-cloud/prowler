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
  status: string; // "FAIL" | "PASS" | "MUTED" (already uppercase)
  impacted_providers: string[];
  resources_total: number;
  resources_fail: number;
  pass_count: number;
  fail_count: number;
  muted_count: number;
  new_count: number;
  changed_count: number;
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
    resourcesTotal: item.attributes.resources_total,
    resourcesFail: item.attributes.resources_fail,
    newCount: item.attributes.new_count,
    changedCount: item.attributes.changed_count,
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
  resource: ResourceInfo;
  provider: ProviderInfo;
  status: string;
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
    findingId: item.id,
    checkId,
    providerType: (item.attributes.provider?.type || "aws") as ProviderType,
    providerAlias: item.attributes.provider?.alias || "",
    providerUid: item.attributes.provider?.uid || "",
    resourceName: item.attributes.resource?.name || "-",
    resourceGroup: item.attributes.resource?.resource_group || "-",
    resourceUid: item.attributes.resource?.uid || "-",
    service: item.attributes.resource?.service || "-",
    region: item.attributes.resource?.region || "-",
    severity: (item.attributes.severity || "informational") as Severity,
    status: item.attributes.status,
    isMuted: item.attributes.status === "MUTED",
    // TODO: remove fallback once the API returns muted_reason in finding-group-resources
    mutedReason: item.attributes.muted_reason || undefined,
    firstSeenAt: item.attributes.first_seen_at,
    lastSeenAt: item.attributes.last_seen_at,
  }));
}
