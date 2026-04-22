import { createDict } from "@/lib";
import type { ProviderType, Severity } from "@/types";

export interface RemediationRecommendation {
  text: string;
  url: string;
}

export interface RemediationCode {
  cli: string;
  other: string;
  nativeiac: string;
  terraform: string;
}

export interface Remediation {
  recommendation: RemediationRecommendation;
  code: RemediationCode;
}

export interface ScanInfo {
  id: string;
  name: string;
  trigger: string;
  state: string;
  uniqueResourceCount: number;
  progress: number;
  duration: number;
  startedAt: string | null;
  completedAt: string | null;
  insertedAt: string | null;
  scheduledAt: string | null;
}

/**
 * Flattened finding for the resource detail drawer.
 * Merges data from the finding attributes, its check_metadata,
 * the included resource, and the included scan/provider.
 */
export interface ResourceDrawerFinding {
  id: string;
  uid: string;
  checkId: string;
  checkTitle: string;
  status: string;
  severity: Severity;
  delta: string | null;
  isMuted: boolean;
  mutedReason: string | null;
  firstSeenAt: string | null;
  updatedAt: string | null;
  // Resource
  resourceId: string;
  resourceUid: string;
  resourceName: string;
  resourceService: string;
  resourceRegion: string;
  resourceType: string;
  resourceGroup: string;
  // Provider
  providerType: ProviderType;
  providerAlias: string;
  providerUid: string;
  // Check metadata (flattened)
  risk: string;
  description: string;
  statusExtended: string;
  complianceFrameworks: string[];
  categories: string[];
  remediation: Remediation;
  additionalUrls: string[];
  // Scan
  scan: ScanInfo | null;
}

/**
 * Extracts unique compliance framework names from available data.
 *
 * Supports three shapes:
 * 1a. check_metadata.compliance — array of { Framework, Version, ... } objects
 *     e.g. [{ Framework: "CIS-AWS", Version: "1.4" }, { Framework: "PCI-DSS" }]
 * 1b. check_metadata.compliance — dict with framework keys and control arrays
 *     e.g. {"CIS-1.4": ["1.6"], "GDPR": ["article_25"], "HIPAA": ["164_312_d"]}
 * 2.  finding.compliance — dict with versioned keys (when API exposes it)
 *     e.g. {"CIS-AWS-1.4": ["2.1"], "PCI-DSS-3.2": ["6.2"]}
 */
function extractComplianceFrameworks(
  metaCompliance: unknown,
  findingCompliance: Record<string, string[]> | null | undefined,
): string[] {
  const frameworks = new Set<string>();

  // Source 1a: check_metadata.compliance — array of objects with Framework field
  if (Array.isArray(metaCompliance)) {
    for (const entry of metaCompliance) {
      if (entry?.Framework || entry?.framework) {
        frameworks.add(entry.Framework || entry.framework);
      }
    }
  }
  // Source 1b: check_metadata.compliance — dict keyed by framework name
  else if (metaCompliance && typeof metaCompliance === "object") {
    for (const key of Object.keys(metaCompliance as Record<string, unknown>)) {
      const base = key.replace(/-\d+(\.\d+)*$/, "");
      frameworks.add(base);
    }
  }

  // Source 2: finding.compliance — dict keys like "CIS-AWS-1.4"
  if (findingCompliance && typeof findingCompliance === "object") {
    for (const key of Object.keys(findingCompliance)) {
      const base = key.replace(/-\d+(\.\d+)*$/, "");
      frameworks.add(base);
    }
  }

  return Array.from(frameworks).sort((a, b) =>
    a.localeCompare(b, undefined, { sensitivity: "base" }),
  );
}

/**
 * Internal shape of a finding item returned by the
 * `/findings/latest?include=resources,scan.provider` endpoint.
 */
interface FindingApiAttributes {
  uid: string;
  check_id: string;
  status: string;
  severity: string;
  delta?: string | null;
  muted?: boolean;
  muted_reason?: string | null;
  first_seen_at?: string | null;
  updated_at?: string | null;
  status_extended?: string;
  compliance?: Record<string, string[]>;
  check_metadata?: Record<string, unknown>;
}

interface FindingApiItem {
  id: string;
  attributes: FindingApiAttributes;
  relationships?: {
    resources?: { data?: Array<{ id: string }> };
    scan?: { data?: { id: string } | null };
  };
}

/** Shape of an included JSON:API resource/scan/provider entry returned by createDict. */
interface IncludedItem {
  id?: string;
  attributes?: Record<string, unknown>;
  relationships?: Record<string, unknown>;
}

/** Lookup dict returned by createDict(). */
type IncludedDict = Record<string, IncludedItem>;

/**
 * Transforms the `/findings/latest?include=resources,scan.provider` response
 * into a flat ResourceDrawerFinding array.
 *
 * Uses createDict to build lookup maps from the JSON:API `included` array,
 * then resolves each finding's resource and provider relationships.
 */
interface JsonApiResponse {
  data: FindingApiItem | FindingApiItem[];
  included?: Record<string, unknown>[];
}

function isJsonApiResponse(value: unknown): value is JsonApiResponse {
  const data = (value as { data?: unknown })?.data;

  return (
    value !== null &&
    typeof value === "object" &&
    "data" in value &&
    (Array.isArray(data) || (data !== null && typeof data === "object"))
  );
}

export function adaptFindingsByResourceResponse(
  apiResponse: unknown,
): ResourceDrawerFinding[] {
  if (!isJsonApiResponse(apiResponse)) {
    return [];
  }

  const resourcesDict = createDict("resources", apiResponse) as IncludedDict;
  const scansDict = createDict("scans", apiResponse) as IncludedDict;
  const providersDict = createDict("providers", apiResponse) as IncludedDict;
  const findings = Array.isArray(apiResponse.data)
    ? apiResponse.data
    : [apiResponse.data];

  return findings.map((item) => {
    const attrs = item.attributes;
    const meta = (attrs.check_metadata || {}) as Record<string, unknown>;
    const remediationRaw = meta.remediation as
      | Record<string, unknown>
      | undefined;
    const remediation = remediationRaw || {
      recommendation: { text: "", url: "" },
      code: { cli: "", other: "", nativeiac: "", terraform: "" },
    };

    // Resolve resource from included
    const resourceRel = item.relationships?.resources?.data?.[0];
    const resource: IncludedItem | null = resourceRel
      ? (resourcesDict[resourceRel.id] ?? null)
      : null;
    const resourceAttrs = (resource?.attributes || {}) as Record<
      string,
      unknown
    >;

    // Resolve provider via scan → provider (include path: scan.provider)
    const scanRel = item.relationships?.scan?.data;
    const scan: IncludedItem | null = scanRel
      ? (scansDict[scanRel.id] ?? null)
      : null;
    const scanRels = scan?.relationships as Record<string, unknown> | undefined;
    const providerRelId =
      ((
        (scanRels?.provider as Record<string, unknown> | undefined)?.data as
          | Record<string, unknown>
          | undefined
      )?.id as string | null) ?? null;
    const provider: IncludedItem | null = providerRelId
      ? (providersDict[providerRelId] ?? null)
      : null;
    const providerAttrs = (provider?.attributes || {}) as Record<
      string,
      unknown
    >;

    const remRec = remediation.recommendation as
      | Record<string, unknown>
      | undefined;
    const remCode = remediation.code as Record<string, unknown> | undefined;

    return {
      id: item.id,
      uid: attrs.uid,
      checkId: attrs.check_id,
      checkTitle: (meta.checktitle as string | undefined) || attrs.check_id,
      status: attrs.status,
      severity: (attrs.severity || "informational") as Severity,
      delta: attrs.delta || null,
      isMuted: Boolean(attrs.muted),
      mutedReason: attrs.muted_reason || null,
      firstSeenAt: attrs.first_seen_at || null,
      updatedAt: attrs.updated_at || null,
      // Resource
      resourceId: resourceRel?.id || "",
      resourceUid: (resourceAttrs.uid as string | undefined) || "-",
      resourceName: (resourceAttrs.name as string | undefined) || "-",
      resourceService: (resourceAttrs.service as string | undefined) || "-",
      resourceRegion: (resourceAttrs.region as string | undefined) || "-",
      resourceType: (resourceAttrs.type as string | undefined) || "-",
      resourceGroup: (meta.resourcegroup as string | undefined) || "-",
      // Provider
      providerType: ((providerAttrs.provider as string | undefined) ||
        "aws") as ProviderType,
      providerAlias: (providerAttrs.alias as string | undefined) || "",
      providerUid: (providerAttrs.uid as string | undefined) || "",
      // Check metadata
      risk: (meta.risk as string | undefined) || "",
      description: (meta.description as string | undefined) || "",
      statusExtended: attrs.status_extended || "",
      complianceFrameworks: extractComplianceFrameworks(
        (meta.compliance ?? meta.Compliance) as unknown,
        attrs.compliance,
      ),
      categories: (meta.categories as string[] | undefined) || [],
      remediation: {
        recommendation: {
          text: (remRec?.text as string | undefined) || "",
          url: (remRec?.url as string | undefined) || "",
        },
        code: {
          cli: (remCode?.cli as string | undefined) || "",
          other: (remCode?.other as string | undefined) || "",
          nativeiac: (remCode?.nativeiac as string | undefined) || "",
          terraform: (remCode?.terraform as string | undefined) || "",
        },
      },
      additionalUrls: (meta.additionalurls as string[] | undefined) || [],
      // Scan
      scan: scan?.attributes
        ? {
            id: (scan.id as string | undefined) || "",
            name: (scan.attributes.name as string | undefined) || "",
            trigger: (scan.attributes.trigger as string | undefined) || "",
            state: (scan.attributes.state as string | undefined) || "",
            uniqueResourceCount:
              (scan.attributes.unique_resource_count as number | undefined) ||
              0,
            progress: (scan.attributes.progress as number | undefined) || 0,
            duration: (scan.attributes.duration as number | undefined) || 0,
            startedAt:
              (scan.attributes.started_at as string | undefined) || null,
            completedAt:
              (scan.attributes.completed_at as string | undefined) || null,
            insertedAt:
              (scan.attributes.inserted_at as string | undefined) || null,
            scheduledAt:
              (scan.attributes.scheduled_at as string | undefined) || null,
          }
        : null,
    };
  });
}
