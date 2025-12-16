import { getProviderDisplayName } from "@/types/providers";

export interface SankeyNode {
  name: string;
}

export interface SankeyLink {
  source: number;
  target: number;
  value: number;
}

export interface ZeroDataProvider {
  id: string;
  displayName: string;
}

export interface SankeyData {
  nodes: SankeyNode[];
  links: SankeyLink[];
  zeroDataProviders: ZeroDataProvider[];
}

export interface SeverityData {
  critical: number;
  high: number;
  medium: number;
  low: number;
  informational: number;
}

export interface SeverityByProviderType {
  [providerType: string]: SeverityData;
}

const SEVERITY_ORDER = [
  "Critical",
  "High",
  "Medium",
  "Low",
  "Informational",
] as const;

const SEVERITY_KEYS: (keyof SeverityData)[] = [
  "critical",
  "high",
  "medium",
  "low",
  "informational",
];

/**
 * Adapts severity by provider type data to Sankey chart format.
 *
 * @param severityByProviderType - Severity breakdown per provider type from the API
 * @param selectedProviderTypes - Provider types that were selected but may have no data
 */
export function adaptToSankeyData(
  severityByProviderType: SeverityByProviderType,
  selectedProviderTypes?: string[],
): SankeyData {
  if (Object.keys(severityByProviderType).length === 0) {
    // No data - check if there are selected providers to show as zero-data
    const zeroDataProviders: ZeroDataProvider[] = (
      selectedProviderTypes || []
    ).map((type) => ({
      id: type.toLowerCase(),
      displayName: getProviderDisplayName(type),
    }));
    return { nodes: [], links: [], zeroDataProviders };
  }

  // Calculate total fails per provider to identify which have data
  const providersWithData: {
    id: string;
    displayName: string;
    totalFail: number;
  }[] = [];
  const providersWithoutData: ZeroDataProvider[] = [];

  for (const [providerType, severity] of Object.entries(
    severityByProviderType,
  )) {
    const totalFail =
      severity.critical +
      severity.high +
      severity.medium +
      severity.low +
      severity.informational;

    const normalizedType = providerType.toLowerCase();

    if (totalFail > 0) {
      providersWithData.push({
        id: normalizedType,
        displayName: getProviderDisplayName(normalizedType),
        totalFail,
      });
    } else {
      providersWithoutData.push({
        id: normalizedType,
        displayName: getProviderDisplayName(normalizedType),
      });
    }
  }

  // Add selected provider types that are not in the response at all
  if (selectedProviderTypes && selectedProviderTypes.length > 0) {
    const existingProviderIds = new Set(
      Object.keys(severityByProviderType).map((t) => t.toLowerCase()),
    );

    for (const selectedType of selectedProviderTypes) {
      const normalizedType = selectedType.toLowerCase();
      if (!existingProviderIds.has(normalizedType)) {
        providersWithoutData.push({
          id: normalizedType,
          displayName: getProviderDisplayName(normalizedType),
        });
      }
    }
  }

  // If no providers have failures, return empty chart with zero-data legends
  if (providersWithData.length === 0) {
    return { nodes: [], links: [], zeroDataProviders: providersWithoutData };
  }

  // Build nodes: providers first, then severities
  const providerNodes: SankeyNode[] = providersWithData.map((p) => ({
    name: p.displayName,
  }));
  const severityNodes: SankeyNode[] = SEVERITY_ORDER.map((severity) => ({
    name: severity,
  }));
  const nodes = [...providerNodes, ...severityNodes];

  // Build links
  const severityStartIndex = providerNodes.length;
  const links: SankeyLink[] = [];

  providersWithData.forEach((provider, sourceIndex) => {
    const severity =
      severityByProviderType[provider.id] ||
      severityByProviderType[provider.id.toUpperCase()];

    if (severity) {
      SEVERITY_KEYS.forEach((key, severityIndex) => {
        const value = severity[key];
        if (value > 0) {
          links.push({
            source: sourceIndex,
            target: severityStartIndex + severityIndex,
            value,
          });
        }
      });
    }
  });

  return { nodes, links, zeroDataProviders: providersWithoutData };
}
