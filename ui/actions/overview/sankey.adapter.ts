import { getProviderDisplayName } from "@/types/providers";

import {
  FindingsSeverityOverviewResponse,
  ProviderOverview,
  ProvidersOverviewResponse,
} from "./types";

export interface SankeyNode {
  name: string;
}

export interface SankeyLink {
  source: number;
  target: number;
  value: number;
}

export interface SankeyData {
  nodes: SankeyNode[];
  links: SankeyLink[];
}

interface AggregatedProvider {
  id: string;
  displayName: string;
  pass: number;
  fail: number;
}

const EXCLUDED_PROVIDERS = new Set(["mongo", "mongodb", "mongodbatlas"]);

// API can return multiple entries for the same provider type, so we sum their findings
function aggregateProvidersByType(
  providers: ProviderOverview[],
): AggregatedProvider[] {
  const aggregated = new Map<string, AggregatedProvider>();

  for (const provider of providers) {
    const { id, attributes } = provider;

    if (EXCLUDED_PROVIDERS.has(id)) continue;

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
 */
export function adaptProvidersOverviewToSankey(
  providersResponse: ProvidersOverviewResponse | undefined,
  severityResponse?: FindingsSeverityOverviewResponse | undefined,
): SankeyData {
  if (!providersResponse?.data || providersResponse.data.length === 0) {
    return { nodes: [], links: [] };
  }

  const aggregatedProviders = aggregateProvidersByType(providersResponse.data);
  const providersWithFailures = aggregatedProviders.filter((p) => p.fail > 0);

  if (providersWithFailures.length === 0) {
    return { nodes: [], links: [] };
  }

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

  return { nodes, links };
}
