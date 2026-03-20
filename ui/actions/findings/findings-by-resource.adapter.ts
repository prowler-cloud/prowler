import { createDict } from "@/lib";
import { ProviderType, Severity } from "@/types";

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
  resourceUid: string;
  resourceName: string;
  resourceService: string;
  resourceRegion: string;
  resourceType: string;
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
}

/**
 * Extracts unique compliance framework names from available data.
 *
 * Supports two shapes:
 * 1. check_metadata.compliance — array of { Framework, Version, ... } objects
 *    e.g. [{ Framework: "CIS-AWS", Version: "1.4" }, { Framework: "PCI-DSS" }]
 * 2. finding.compliance — dict with versioned keys (when API exposes it)
 *    e.g. {"CIS-AWS-1.4": ["2.1"], "PCI-DSS-3.2": ["6.2"]}
 */
function extractComplianceFrameworks(
  metaCompliance: unknown,
  findingCompliance: Record<string, string[]> | null | undefined,
): string[] {
  const frameworks = new Set<string>();

  // Source 1: check_metadata.compliance — array of objects with Framework field
  if (Array.isArray(metaCompliance)) {
    for (const entry of metaCompliance) {
      if (entry?.Framework || entry?.framework) {
        frameworks.add(entry.Framework || entry.framework);
      }
    }
  }

  // Source 2: finding.compliance — dict keys like "CIS-AWS-1.4"
  if (findingCompliance && typeof findingCompliance === "object") {
    for (const key of Object.keys(findingCompliance)) {
      const base = key.replace(/-\d+(\.\d+)*$/, "");
      frameworks.add(base);
    }
  }

  return Array.from(frameworks);
}

/**
 * Transforms the `/findings/latest?include=resources,scan.provider` response
 * into a flat ResourceDrawerFinding array.
 *
 * Uses createDict to build lookup maps from the JSON:API `included` array,
 * then resolves each finding's resource and provider relationships.
 */
export function adaptFindingsByResourceResponse(
  apiResponse: any,
): ResourceDrawerFinding[] {
  if (!apiResponse?.data || !Array.isArray(apiResponse.data)) {
    return [];
  }

  const resourcesDict = createDict("resources", apiResponse);
  const scansDict = createDict("scans", apiResponse);
  const providersDict = createDict("providers", apiResponse);

  return apiResponse.data.map((item: any) => {
    const attrs = item.attributes;
    const meta = attrs.check_metadata || {};
    const remediation = meta.remediation || {
      recommendation: { text: "", url: "" },
      code: { cli: "", other: "", nativeiac: "", terraform: "" },
    };

    // Resolve resource from included
    const resourceRel = item.relationships?.resources?.data?.[0];
    const resource = resourceRel ? resourcesDict[resourceRel.id] : null;
    const resourceAttrs = resource?.attributes || {};

    // Resolve provider via scan → provider (include path: scan.provider)
    const scanRel = item.relationships?.scan?.data;
    const scan = scanRel ? scansDict[scanRel.id] : null;
    const providerRelId = scan?.relationships?.provider?.data?.id ?? null;
    const provider = providerRelId ? providersDict[providerRelId] : null;
    const providerAttrs = provider?.attributes || {};

    return {
      id: item.id,
      uid: attrs.uid,
      checkId: attrs.check_id,
      checkTitle: meta.checktitle || attrs.check_id,
      status: attrs.status,
      severity: (attrs.severity || "informational") as Severity,
      delta: attrs.delta || null,
      isMuted: Boolean(attrs.muted),
      mutedReason: attrs.muted_reason || null,
      firstSeenAt: attrs.first_seen_at || null,
      updatedAt: attrs.updated_at || null,
      // Resource
      resourceUid: resourceAttrs.uid || "-",
      resourceName: resourceAttrs.name || "-",
      resourceService: resourceAttrs.service || "-",
      resourceRegion: resourceAttrs.region || "-",
      resourceType: resourceAttrs.type || "-",
      // Provider
      providerType: (providerAttrs.provider || "aws") as ProviderType,
      providerAlias: providerAttrs.alias || "",
      providerUid: providerAttrs.uid || "",
      // Check metadata
      risk: meta.risk || "",
      description: meta.description || "",
      statusExtended: attrs.status_extended || "",
      complianceFrameworks: extractComplianceFrameworks(
        meta.compliance ?? meta.Compliance,
        attrs.compliance,
      ),
      categories: meta.categories || [],
      remediation: {
        recommendation: {
          text: remediation.recommendation?.text || "",
          url: remediation.recommendation?.url || "",
        },
        code: {
          cli: remediation.code?.cli || "",
          other: remediation.code?.other || "",
          nativeiac: remediation.code?.nativeiac || "",
          terraform: remediation.code?.terraform || "",
        },
      },
      additionalUrls: meta.additionalurls || [],
    };
  });
}
