import {
  FindingsSeverityOverviewResponse,
  ProviderOverview,
  ProvidersOverviewResponse,
  RegionsOverviewResponse,
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

/**
 * Threat map location point structure (matching ThreatMap component)
 */
export interface ThreatMapLocation {
  id: string;
  name: string;
  region: string;
  coordinates: [number, number];
  totalFindings: number;
  riskLevel: "low-high" | "high" | "critical";
  severityData: Array<{ name: string; value: number }>;
  change?: number;
}

/**
 * Threat map data structure (matching ThreatMap component)
 */
export interface ThreatMapData {
  locations: ThreatMapLocation[];
  regions: string[];
}

/**
 * AWS region to coordinates mapping
 */
const AWS_REGION_COORDINATES: Record<string, { lat: number; lng: number }> = {
  "us-east-1": { lat: 37.5, lng: -77.5 }, // N. Virginia
  "us-east-2": { lat: 40.0, lng: -83.0 }, // Ohio
  "us-west-1": { lat: 37.8, lng: -122.4 }, // N. California
  "us-west-2": { lat: 45.5, lng: -122.7 }, // Oregon
  "af-south-1": { lat: -33.9, lng: 18.4 }, // Cape Town
  "ap-east-1": { lat: 22.3, lng: 114.2 }, // Hong Kong
  "ap-south-1": { lat: 19.1, lng: 72.9 }, // Mumbai
  "ap-south-2": { lat: 17.4, lng: 78.5 }, // Hyderabad
  "ap-northeast-1": { lat: 35.7, lng: 139.7 }, // Tokyo
  "ap-northeast-2": { lat: 37.6, lng: 127.0 }, // Seoul
  "ap-northeast-3": { lat: 34.7, lng: 135.5 }, // Osaka
  "ap-southeast-1": { lat: 1.4, lng: 103.8 }, // Singapore
  "ap-southeast-2": { lat: -33.9, lng: 151.2 }, // Sydney
  "ap-southeast-3": { lat: -6.2, lng: 106.8 }, // Jakarta
  "ap-southeast-4": { lat: -37.8, lng: 144.96 }, // Melbourne
  "ca-central-1": { lat: 45.5, lng: -73.6 }, // Montreal
  "ca-west-1": { lat: 51.0, lng: -114.1 }, // Calgary
  "eu-central-1": { lat: 50.1, lng: 8.7 }, // Frankfurt
  "eu-central-2": { lat: 47.4, lng: 8.5 }, // Zurich
  "eu-west-1": { lat: 53.3, lng: -6.3 }, // Ireland
  "eu-west-2": { lat: 51.5, lng: -0.1 }, // London
  "eu-west-3": { lat: 48.9, lng: 2.3 }, // Paris
  "eu-north-1": { lat: 59.3, lng: 18.1 }, // Stockholm
  "eu-south-1": { lat: 45.5, lng: 9.2 }, // Milan
  "eu-south-2": { lat: 40.4, lng: -3.7 }, // Spain
  "il-central-1": { lat: 32.1, lng: 34.8 }, // Tel Aviv
  "me-central-1": { lat: 25.3, lng: 55.3 }, // UAE
  "me-south-1": { lat: 26.1, lng: 50.6 }, // Bahrain
  "sa-east-1": { lat: -23.5, lng: -46.6 }, // São Paulo
};

/**
 * Azure region to coordinates mapping
 */
const AZURE_REGION_COORDINATES: Record<string, { lat: number; lng: number }> = {
  eastus: { lat: 37.5, lng: -79.0 },
  eastus2: { lat: 36.7, lng: -78.9 },
  westus: { lat: 37.8, lng: -122.4 },
  westus2: { lat: 47.6, lng: -122.3 },
  westus3: { lat: 33.4, lng: -112.1 },
  centralus: { lat: 41.6, lng: -93.6 },
  northcentralus: { lat: 41.9, lng: -87.6 },
  southcentralus: { lat: 29.4, lng: -98.5 },
  westcentralus: { lat: 40.9, lng: -110.0 },
  canadacentral: { lat: 43.7, lng: -79.4 },
  canadaeast: { lat: 46.8, lng: -71.2 },
  brazilsouth: { lat: -23.5, lng: -46.6 },
  northeurope: { lat: 53.3, lng: -6.3 },
  westeurope: { lat: 52.4, lng: 4.9 },
  uksouth: { lat: 51.5, lng: -0.1 },
  ukwest: { lat: 53.4, lng: -3.0 },
  francecentral: { lat: 46.3, lng: 2.4 },
  francesouth: { lat: 43.8, lng: 2.1 },
  switzerlandnorth: { lat: 47.5, lng: 8.5 },
  switzerlandwest: { lat: 46.2, lng: 6.1 },
  germanywestcentral: { lat: 50.1, lng: 8.7 },
  germanynorth: { lat: 53.1, lng: 8.8 },
  norwayeast: { lat: 59.9, lng: 10.7 },
  norwaywest: { lat: 58.97, lng: 5.73 },
  swedencentral: { lat: 60.67, lng: 17.14 },
  polandcentral: { lat: 52.23, lng: 21.01 },
  italynorth: { lat: 45.5, lng: 9.2 },
  spaincentral: { lat: 40.4, lng: -3.7 },
  australiaeast: { lat: -33.9, lng: 151.2 },
  australiasoutheast: { lat: -37.8, lng: 145.0 },
  australiacentral: { lat: -35.3, lng: 149.1 },
  eastasia: { lat: 22.3, lng: 114.2 },
  southeastasia: { lat: 1.3, lng: 103.8 },
  japaneast: { lat: 35.7, lng: 139.7 },
  japanwest: { lat: 34.7, lng: 135.5 },
  koreacentral: { lat: 37.6, lng: 127.0 },
  koreasouth: { lat: 35.2, lng: 129.0 },
  centralindia: { lat: 18.6, lng: 73.9 },
  southindia: { lat: 12.9, lng: 80.2 },
  westindia: { lat: 19.1, lng: 72.9 },
  uaenorth: { lat: 25.3, lng: 55.3 },
  uaecentral: { lat: 24.5, lng: 54.4 },
  southafricanorth: { lat: -26.2, lng: 28.0 },
  southafricawest: { lat: -34.0, lng: 18.5 },
  israelcentral: { lat: 32.1, lng: 34.8 },
  qatarcentral: { lat: 25.3, lng: 51.5 },
};

/**
 * GCP region to coordinates mapping
 */
const GCP_REGION_COORDINATES: Record<string, { lat: number; lng: number }> = {
  "us-central1": { lat: 41.3, lng: -95.9 }, // Iowa
  "us-east1": { lat: 33.2, lng: -80.0 }, // South Carolina
  "us-east4": { lat: 39.0, lng: -77.5 }, // Northern Virginia
  "us-east5": { lat: 39.96, lng: -82.99 }, // Columbus
  "us-south1": { lat: 32.8, lng: -96.8 }, // Dallas
  "us-west1": { lat: 45.6, lng: -122.8 }, // Oregon
  "us-west2": { lat: 34.1, lng: -118.2 }, // Los Angeles
  "us-west3": { lat: 40.8, lng: -111.9 }, // Salt Lake City
  "us-west4": { lat: 36.2, lng: -115.1 }, // Las Vegas
  "northamerica-northeast1": { lat: 45.5, lng: -73.6 }, // Montreal
  "northamerica-northeast2": { lat: 43.7, lng: -79.4 }, // Toronto
  "southamerica-east1": { lat: -23.5, lng: -46.6 }, // São Paulo
  "southamerica-west1": { lat: -33.4, lng: -70.6 }, // Santiago
  "europe-north1": { lat: 60.6, lng: 27.0 }, // Finland
  "europe-west1": { lat: 50.4, lng: 3.8 }, // Belgium
  "europe-west2": { lat: 51.5, lng: -0.1 }, // London
  "europe-west3": { lat: 50.1, lng: 8.7 }, // Frankfurt
  "europe-west4": { lat: 53.4, lng: 6.8 }, // Netherlands
  "europe-west6": { lat: 47.4, lng: 8.5 }, // Zurich
  "europe-west8": { lat: 45.5, lng: 9.2 }, // Milan
  "europe-west9": { lat: 48.9, lng: 2.3 }, // Paris
  "europe-west10": { lat: 52.5, lng: 13.4 }, // Berlin
  "europe-west12": { lat: 45.0, lng: 7.7 }, // Turin
  "europe-central2": { lat: 52.2, lng: 21.0 }, // Warsaw
  "europe-southwest1": { lat: 40.4, lng: -3.7 }, // Madrid
  "asia-east1": { lat: 24.0, lng: 121.0 }, // Taiwan
  "asia-east2": { lat: 22.3, lng: 114.2 }, // Hong Kong
  "asia-northeast1": { lat: 35.7, lng: 139.7 }, // Tokyo
  "asia-northeast2": { lat: 34.7, lng: 135.5 }, // Osaka
  "asia-northeast3": { lat: 37.6, lng: 127.0 }, // Seoul
  "asia-south1": { lat: 19.1, lng: 72.9 }, // Mumbai
  "asia-south2": { lat: 28.6, lng: 77.2 }, // Delhi
  "asia-southeast1": { lat: 1.4, lng: 103.8 }, // Singapore
  "asia-southeast2": { lat: -6.2, lng: 106.8 }, // Jakarta
  "australia-southeast1": { lat: -33.9, lng: 151.2 }, // Sydney
  "australia-southeast2": { lat: -37.8, lng: 145.0 }, // Melbourne
  "me-central1": { lat: 25.3, lng: 51.5 }, // Doha
  "me-central2": { lat: 24.5, lng: 54.4 }, // Dammam
  "me-west1": { lat: 32.1, lng: 34.8 }, // Tel Aviv
  "africa-south1": { lat: -26.2, lng: 28.0 }, // Johannesburg
};

/**
 * Gets coordinates for a region based on provider type
 * Returns [lng, lat] format for D3/GeoJSON compatibility
 */
function getRegionCoordinates(
  providerType: string,
  region: string,
): [number, number] | null {
  const normalizedRegion = region.toLowerCase();
  let coords: { lat: number; lng: number } | undefined;

  switch (providerType.toLowerCase()) {
    case "aws":
      coords = AWS_REGION_COORDINATES[normalizedRegion];
      break;
    case "azure":
      coords = AZURE_REGION_COORDINATES[normalizedRegion];
      break;
    case "gcp":
      coords = GCP_REGION_COORDINATES[normalizedRegion];
      break;
  }

  // Return [lng, lat] format for D3/GeoJSON
  return coords ? [coords.lng, coords.lat] : null;
}

/**
 * Maps provider type to display region name
 */
const PROVIDER_REGION_NAMES: Record<string, string> = {
  aws: "AWS",
  azure: "Azure",
  gcp: "Google Cloud",
  kubernetes: "Kubernetes",
};

/**
 * Determines risk level based on fail rate
 */
function getRiskLevel(failRate: number): "low-high" | "high" | "critical" {
  if (failRate >= 0.5) return "critical";
  if (failRate >= 0.25) return "high";
  return "low-high";
}

/**
 * Formats a raw region code into a human-readable name
 * Examples:
 *   "europe-west10" → "Europe West 10"
 *   "us-east-1" → "US East 1"
 *   "asia-northeast3" → "Asia Northeast 3"
 */
function formatRegionCode(region: string): string {
  return region
    .split(/[-_]/)
    .map((part) => {
      // Check if the part ends with numbers (e.g., "west10" → "West 10")
      const match = part.match(/^([a-zA-Z]+)(\d+)$/);
      if (match) {
        const [, text, number] = match;
        return `${text.charAt(0).toUpperCase()}${text.slice(1).toLowerCase()} ${number}`;
      }
      // Regular word capitalization
      return part.charAt(0).toUpperCase() + part.slice(1).toLowerCase();
    })
    .join(" ");
}

/**
 * Formats region name for display
 */
function formatRegionName(providerType: string, region: string): string {
  const providerPrefix =
    PROVIDER_REGION_NAMES[providerType.toLowerCase()] || providerType;
  const formattedRegion = formatRegionCode(region);
  return `${providerPrefix} - ${formattedRegion}`;
}

/**
 * Adapts regions overview API response to threat map format
 *
 * @param regionsResponse - Raw API response from /overviews/regions
 * @returns Threat map data with locations and region filters
 */
export function adaptRegionsOverviewToThreatMap(
  regionsResponse: RegionsOverviewResponse | undefined,
): ThreatMapData {
  if (!regionsResponse?.data || regionsResponse.data.length === 0) {
    return {
      locations: [],
      regions: [],
    };
  }

  const locations: ThreatMapLocation[] = [];
  const regionSet = new Set<string>();

  for (const regionData of regionsResponse.data) {
    const { id, attributes } = regionData;
    const coordinates = getRegionCoordinates(
      attributes.provider_type,
      attributes.region,
    );

    // Skip regions without coordinates
    if (!coordinates) continue;

    const providerRegion =
      PROVIDER_REGION_NAMES[attributes.provider_type.toLowerCase()] ||
      attributes.provider_type;
    regionSet.add(providerRegion);

    const failRate =
      attributes.total > 0 ? attributes.fail / attributes.total : 0;

    locations.push({
      id,
      name: formatRegionName(attributes.provider_type, attributes.region),
      region: providerRegion,
      coordinates,
      totalFindings: attributes.fail,
      riskLevel: getRiskLevel(failRate),
      severityData: [
        { name: "Fail", value: attributes.fail },
        { name: "Pass", value: attributes.pass },
        { name: "Muted", value: attributes.muted },
      ],
    });
  }

  return {
    locations,
    regions: Array.from(regionSet).sort(),
  };
}
