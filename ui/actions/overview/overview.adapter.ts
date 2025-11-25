import {
  FindingsSeverityOverviewResponse,
  ProviderOverview,
  ProvidersOverviewResponse,
} from "./types";

/**
 * Sankey chart node structure
 */
export interface SankeyNode {
  name: string;
}

/**
 * Sankey chart link structure
 */
export interface SankeyLink {
  source: number;
  target: number;
  value: number;
}

/**
 * Sankey chart data structure
 */
export interface SankeyData {
  nodes: SankeyNode[];
  links: SankeyLink[];
}

/**
 * Provider display name mapping
 * Maps provider IDs to user-friendly display names
 * These names must match the COLOR_MAP keys in sankey-chart.tsx
 */
const PROVIDER_DISPLAY_NAMES: Record<string, string> = {
  aws: "AWS",
  azure: "Azure",
  gcp: "Google Cloud",
  kubernetes: "Kubernetes",
  github: "GitHub",
  m365: "Microsoft 365",
  iac: "Infrastructure as Code",
  oraclecloud: "Oracle Cloud Infrastructure",
};

/**
 * Aggregated provider data after grouping by provider type
 */
interface AggregatedProvider {
  id: string;
  displayName: string;
  pass: number;
  fail: number;
}

/**
 * Provider types to exclude from the Sankey chart
 */
const EXCLUDED_PROVIDERS = new Set(["mongo", "mongodb", "mongodbatlas"]);

/**
 * Aggregates multiple provider entries by provider type (id)
 * Since the API can return multiple entries for the same provider type,
 * we need to sum up their findings
 *
 * @param providers - Raw provider overview data from API
 * @returns Aggregated providers with summed findings
 */
function aggregateProvidersByType(
  providers: ProviderOverview[],
): AggregatedProvider[] {
  const aggregated = new Map<string, AggregatedProvider>();

  for (const provider of providers) {
    const { id, attributes } = provider;

    // Skip excluded providers
    if (EXCLUDED_PROVIDERS.has(id)) {
      continue;
    }

    const existing = aggregated.get(id);

    if (existing) {
      existing.pass += attributes.findings.pass;
      existing.fail += attributes.findings.fail;
    } else {
      aggregated.set(id, {
        id,
        displayName: PROVIDER_DISPLAY_NAMES[id] || id,
        pass: attributes.findings.pass,
        fail: attributes.findings.fail,
      });
    }
  }

  return Array.from(aggregated.values());
}

/**
 * Severity display names in order
 */
const SEVERITY_ORDER = [
  "Critical",
  "High",
  "Medium",
  "Low",
  "Informational",
] as const;

/**
 * Adapts providers overview and findings severity API responses to Sankey chart format
 *
 * Creates a 2-level flow visualization:
 * - Level 1: Cloud providers (AWS, Azure, GCP, etc.)
 * - Level 2: Severity breakdown (Critical, High, Medium, Low, Informational)
 *
 * The severity distribution is calculated proportionally based on each provider's
 * fail count relative to the total fails across all providers.
 *
 * @param providersResponse - Raw API response from /overviews/providers
 * @param severityResponse - Raw API response from /overviews/findings_severity
 * @returns Sankey chart data with nodes and links
 */
export function adaptProvidersOverviewToSankey(
  providersResponse: ProvidersOverviewResponse | undefined,
  severityResponse?: FindingsSeverityOverviewResponse | undefined,
): SankeyData {
  if (!providersResponse?.data || providersResponse.data.length === 0) {
    return { nodes: [], links: [] };
  }

  // Aggregate providers by type
  const aggregatedProviders = aggregateProvidersByType(providersResponse.data);

  // Filter out providers with no findings (only need fail > 0 for severity view)
  const providersWithFailures = aggregatedProviders.filter((p) => p.fail > 0);

  if (providersWithFailures.length === 0) {
    return { nodes: [], links: [] };
  }

  // Build nodes array: providers first, then severities
  const providerNodes: SankeyNode[] = providersWithFailures.map((p) => ({
    name: p.displayName,
  }));

  const severityNodes: SankeyNode[] = SEVERITY_ORDER.map((severity) => ({
    name: severity,
  }));

  const nodes = [...providerNodes, ...severityNodes];

  // Calculate severity start index (after provider nodes)
  const severityStartIndex = providerNodes.length;

  // Build links from each provider to severities
  const links: SankeyLink[] = [];

  // If we have severity data, distribute proportionally
  if (severityResponse?.data?.attributes) {
    const { critical, high, medium, low, informational } =
      severityResponse.data.attributes;

    const severityValues = [critical, high, medium, low, informational];
    const totalSeverity = severityValues.reduce((sum, v) => sum + v, 0);

    if (totalSeverity > 0) {
      // Calculate total fails across all providers
      const totalFails = providersWithFailures.reduce(
        (sum, p) => sum + p.fail,
        0,
      );

      providersWithFailures.forEach((provider, sourceIndex) => {
        // Calculate this provider's proportion of total fails
        const providerRatio = provider.fail / totalFails;

        severityValues.forEach((severityValue, severityIndex) => {
          // Distribute severity proportionally to this provider
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
    // Fallback: if no severity data, just show fail counts to a generic "Fail" node
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

  return { nodes, links };
}
