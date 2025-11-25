import { ProviderOverview, ProvidersOverviewResponse } from "./types";

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
 * Adapts providers overview API response to Sankey chart format
 *
 * Creates a flow visualization from:
 * - Source nodes: Cloud providers (AWS, Azure, GCP, etc.)
 * - Target nodes: Finding statuses (Pass, Fail)
 * - Links: Number of findings flowing from each provider to each status
 *
 * @param response - Raw API response from /overviews/providers
 * @returns Sankey chart data with nodes and links
 */
export function adaptProvidersOverviewToSankey(
  response: ProvidersOverviewResponse | undefined,
): SankeyData {
  if (!response?.data || response.data.length === 0) {
    return { nodes: [], links: [] };
  }

  // Aggregate providers by type
  const aggregatedProviders = aggregateProvidersByType(response.data);

  // Filter out providers with no findings
  const providersWithFindings = aggregatedProviders.filter(
    (p) => p.pass > 0 || p.fail > 0,
  );

  if (providersWithFindings.length === 0) {
    return { nodes: [], links: [] };
  }

  // Build nodes array: providers first, then statuses
  const providerNodes: SankeyNode[] = providersWithFindings.map((p) => ({
    name: p.displayName,
  }));

  const statusNodes: SankeyNode[] = [{ name: "Pass" }, { name: "Fail" }];

  const nodes = [...providerNodes, ...statusNodes];

  // Calculate target indices (statuses come after providers)
  const passIndex = providerNodes.length;
  const failIndex = providerNodes.length + 1;

  // Build links from each provider to Pass/Fail
  const links: SankeyLink[] = [];

  providersWithFindings.forEach((provider, sourceIndex) => {
    if (provider.pass > 0) {
      links.push({
        source: sourceIndex,
        target: passIndex,
        value: provider.pass,
      });
    }

    if (provider.fail > 0) {
      links.push({
        source: sourceIndex,
        target: failIndex,
        value: provider.fail,
      });
    }
  });

  return { nodes, links };
}
