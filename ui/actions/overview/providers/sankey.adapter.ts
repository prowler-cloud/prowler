import { getProviderDisplayName } from "@/types/providers";

import {
  FindingsSeverityOverviewResponse,
  ProviderOverview,
  ProvidersOverviewResponse,
} from "../types";

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

export interface SankeyFilters {
  providerTypes?: string[];
  /** All selected provider types - used to show missing providers in legend */
  allSelectedProviderTypes?: string[];
}

interface AggregatedProvider {
  id: string;
  displayName: string;
  pass: number;
  fail: number;
}

// API can return multiple entries for the same provider type, so we sum their findings
function aggregateProvidersByType(
  providers: ProviderOverview[],
): AggregatedProvider[] {
  const aggregated = new Map<string, AggregatedProvider>();

  for (const provider of providers) {
    const { id, attributes } = provider;

    const existing = aggregated.get(id);

    if (existing) {
      existing.pass += attributes.findings.pass;
      existing.fail += attributes.findings.fail;
    } else {
      aggregated.set(id, {
        id,
        displayName: getProviderDisplayName(id),
        pass: attributes.findings.pass,
        fail: attributes.findings.fail,
      });
    }
  }

  return Array.from(aggregated.values());
}

const SEVERITY_ORDER = [
  "Critical",
  "High",
  "Medium",
  "Low",
  "Informational",
] as const;

/**
 * Adapts providers overview and findings severity API responses to Sankey chart format.
 * Severity distribution is calculated proportionally based on each provider's fail count.
 *
 * @param providersResponse - The providers overview API response
 * @param severityResponse - The findings severity API response
 * @param filters - Optional filters to restrict which providers are shown.
 *                  When filters are set, only selected providers are shown.
 *                  When no filters, all providers are shown.
 */
export function adaptProvidersOverviewToSankey(
  providersResponse: ProvidersOverviewResponse | undefined,
  severityResponse?: FindingsSeverityOverviewResponse | undefined,
  filters?: SankeyFilters,
): SankeyData {
  if (!providersResponse?.data || providersResponse.data.length === 0) {
    return { nodes: [], links: [], zeroDataProviders: [] };
  }

  const aggregatedProviders = aggregateProvidersByType(providersResponse.data);

  // Filter providers based on selection:
  // - If providerTypes filter is set: show only those provider types
  // - Otherwise: show all providers from the API response
  const hasProviderTypeFilter =
    filters?.providerTypes && filters.providerTypes.length > 0;

  let providersToShow: AggregatedProvider[];
  if (hasProviderTypeFilter) {
    // Show only selected provider types
    providersToShow = aggregatedProviders.filter((p) =>
      filters.providerTypes!.includes(p.id.toLowerCase()),
    );
  } else {
    // No provider type filter - show all providers from the API response
    // Providers with no findings (pass=0, fail=0) will appear in the legend
    providersToShow = aggregatedProviders;
  }

  if (providersToShow.length === 0) {
    return { nodes: [], links: [], zeroDataProviders: [] };
  }

  // Separate providers with and without failures
  const providersWithFailures = providersToShow.filter((p) => p.fail > 0);
  const providersWithoutFailures = providersToShow.filter((p) => p.fail === 0);

  // Zero-data providers to show as legends below the chart
  const zeroDataProviders: ZeroDataProvider[] = providersWithoutFailures.map(
    (p) => ({
      id: p.id,
      displayName: p.displayName,
    }),
  );

  // Add selected provider types that are completely missing from API response
  // (these are providers with zero findings - not even in the response)
  if (
    filters?.allSelectedProviderTypes &&
    filters.allSelectedProviderTypes.length > 0
  ) {
    const existingProviderIds = new Set(
      aggregatedProviders.map((p) => p.id.toLowerCase()),
    );

    for (const selectedType of filters.allSelectedProviderTypes) {
      const normalizedType = selectedType.toLowerCase();
      if (!existingProviderIds.has(normalizedType)) {
        // This provider type was selected but has no data at all
        zeroDataProviders.push({
          id: normalizedType,
          displayName: getProviderDisplayName(normalizedType),
        });
      }
    }
  }

  // If no providers have failures, return empty chart with legends
  if (providersWithFailures.length === 0) {
    return { nodes: [], links: [], zeroDataProviders };
  }

  // Only include providers WITH failures in the chart
  const providerNodes: SankeyNode[] = providersWithFailures.map((p) => ({
    name: p.displayName,
  }));
  const severityNodes: SankeyNode[] = SEVERITY_ORDER.map((severity) => ({
    name: severity,
  }));
  const nodes = [...providerNodes, ...severityNodes];
  const severityStartIndex = providerNodes.length;
  const links: SankeyLink[] = [];

  if (severityResponse?.data?.attributes) {
    const { critical, high, medium, low, informational } =
      severityResponse.data.attributes;

    const severityValues = [critical, high, medium, low, informational];
    const totalSeverity = severityValues.reduce((sum, v) => sum + v, 0);

    if (totalSeverity > 0) {
      const totalFails = providersWithFailures.reduce(
        (sum, p) => sum + p.fail,
        0,
      );

      providersWithFailures.forEach((provider, sourceIndex) => {
        const providerRatio = provider.fail / totalFails;

        severityValues.forEach((severityValue, severityIndex) => {
          const value = Math.round(severityValue * providerRatio);

          if (value > 0) {
            links.push({
              source: sourceIndex,
              target: severityStartIndex + severityIndex,
              value,
            });
          }
        });
      });
    }
  } else {
    // Fallback when no severity data available
    const failNode: SankeyNode = { name: "Fail" };
    nodes.push(failNode);
    const failIndex = nodes.length - 1;

    providersWithFailures.forEach((provider, sourceIndex) => {
      links.push({
        source: sourceIndex,
        target: failIndex,
        value: provider.fail,
      });
    });
  }

  return { nodes, links, zeroDataProviders };
}
