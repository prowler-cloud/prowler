import { createDict } from "@/lib";
import type { FindingProps } from "@/types/components";
import type { FindingResourceRow } from "@/types/findings-table";
import type { ProviderType } from "@/types/providers";

interface JsonApiFindingResponse {
  data?: FindingProps;
  included?: Record<string, unknown>[];
}

export function expandFindingWithRelationships(
  apiResponse: JsonApiFindingResponse | undefined,
): FindingProps | null {
  if (!apiResponse?.data) {
    return null;
  }

  const resourceDict = createDict("resources", apiResponse);
  const scanDict = createDict("scans", apiResponse);
  const providerDict = createDict("providers", apiResponse);

  const finding = apiResponse.data;
  const scan = scanDict[finding.relationships?.scan?.data?.id];
  const resource =
    resourceDict[finding.relationships?.resources?.data?.[0]?.id];
  const provider = providerDict[scan?.relationships?.provider?.data?.id];

  return {
    ...finding,
    relationships: { ...finding.relationships, scan, resource, provider },
  } as FindingProps;
}

export function findingToFindingResourceRow(
  finding: FindingProps,
): FindingResourceRow {
  const resource = finding.relationships?.resource?.attributes;
  const provider = finding.relationships?.provider?.attributes;

  return {
    id: finding.id,
    rowType: "resource",
    findingId: finding.id,
    checkId: finding.attributes.check_id,
    providerType: (provider?.provider || "aws") as ProviderType,
    providerAlias: provider?.alias || "-",
    providerUid: provider?.uid || "-",
    resourceName: resource?.name || "-",
    resourceType: resource?.type || "-",
    resourceGroup: "-",
    resourceUid: resource?.uid || "-",
    service: resource?.service || "-",
    region: resource?.region || "-",
    severity: finding.attributes.severity,
    status: finding.attributes.status,
    delta: finding.attributes.delta,
    isMuted: finding.attributes.muted,
    mutedReason: finding.attributes.muted_reason,
    firstSeenAt: finding.attributes.first_seen_at,
    lastSeenAt: finding.attributes.updated_at,
  };
}
