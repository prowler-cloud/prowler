import { getProviderDisplayName } from "@/types/providers";

import { RegionsOverviewResponse } from "./types";

export const RISK_LEVELS = {
  LOW_HIGH: "low-high",
  HIGH: "high",
  CRITICAL: "critical",
} as const;

export type RiskLevel = (typeof RISK_LEVELS)[keyof typeof RISK_LEVELS];

export interface ThreatMapLocation {
  id: string;
  name: string;
  region: string;
  regionCode: string;
  providerType: string;
  coordinates: [number, number];
  totalFindings: number;
  failFindings: number;
  riskLevel: RiskLevel;
  severityData: Array<{
    name: string;
    value: number;
    percentage?: number;
    color?: string;
  }>;
  change?: number;
}

export interface ThreatMapData {
  locations: ThreatMapLocation[];
  regions: string[];
}

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
  // Add global as default fallback for any unrecognized GCP region
  global: { lat: 37.4, lng: -122.1 }, // Mountain View, CA (Google HQ)
};

// Kubernetes can run anywhere, using global fallback for any region
const KUBERNETES_COORDINATES: Record<string, { lat: number; lng: number }> = {
  global: { lat: 37.7, lng: -122.4 }, // Global fallback
};

// M365 regions (Microsoft datacenter locations)
const M365_COORDINATES: Record<string, { lat: number; lng: number }> = {
  global: { lat: 47.6, lng: -122.3 }, // Global fallback
};

// GitHub regions
const GITHUB_COORDINATES: Record<string, { lat: number; lng: number }> = {
  global: { lat: 37.8, lng: -122.4 }, // Global fallback
};

// IAC has no regions - it's code scanning
const IAC_COORDINATES: Record<string, { lat: number; lng: number }> = {
  global: { lat: 40.7, lng: -74.0 }, // Global fallback
};

// Oracle Cloud Infrastructure regions
const ORACLECLOUD_COORDINATES: Record<string, { lat: number; lng: number }> = {
  // Americas
  "us-phoenix-1": { lat: 33.4, lng: -112.1 },
  "us-ashburn-1": { lat: 39.0, lng: -77.5 },
  "us-sanjose-1": { lat: 37.3, lng: -121.9 },
  "ca-toronto-1": { lat: 43.7, lng: -79.4 },
  "ca-montreal-1": { lat: 45.5, lng: -73.6 },
  "sa-saopaulo-1": { lat: -23.5, lng: -46.6 },
  "sa-santiago-1": { lat: -33.4, lng: -70.6 },
  // Europe
  "uk-london-1": { lat: 51.5, lng: -0.1 },
  "eu-frankfurt-1": { lat: 50.1, lng: 8.7 },
  "eu-zurich-1": { lat: 47.4, lng: 8.5 },
  "eu-amsterdam-1": { lat: 52.4, lng: 4.9 },
  "eu-paris-1": { lat: 48.9, lng: 2.3 },
  "eu-marseille-1": { lat: 43.3, lng: 5.4 },
  "eu-stockholm-1": { lat: 59.3, lng: 18.1 },
  "eu-milan-1": { lat: 45.5, lng: 9.2 },
  // Middle East & Africa
  "me-jeddah-1": { lat: 21.5, lng: 39.2 },
  "me-dubai-1": { lat: 25.3, lng: 55.3 },
  "il-jerusalem-1": { lat: 31.8, lng: 35.2 },
  "af-johannesburg-1": { lat: -26.2, lng: 28.0 },
  // Asia Pacific
  "ap-mumbai-1": { lat: 19.1, lng: 72.9 },
  "ap-tokyo-1": { lat: 35.7, lng: 139.7 },
  "ap-osaka-1": { lat: 34.7, lng: 135.5 },
  "ap-seoul-1": { lat: 37.6, lng: 127.0 },
  "ap-sydney-1": { lat: -33.9, lng: 151.2 },
  "ap-melbourne-1": { lat: -37.8, lng: 145.0 },
  "ap-singapore-1": { lat: 1.3, lng: 103.8 },
  "ap-hyderabad-1": { lat: 17.4, lng: 78.5 },
  "ap-chuncheon-1": { lat: 37.9, lng: 127.7 },
  global: { lat: 37.5, lng: -122.3 }, // Global fallback
};

// MongoDB Atlas runs on AWS/Azure/GCP infrastructure
// Using global fallback since it inherits regions from underlying cloud provider
const MONGODBATLAS_COORDINATES: Record<string, { lat: number; lng: number }> = {
  global: { lat: 40.8, lng: -74.0 }, // Global fallback
};

// Alibaba Cloud regions
const ALIBABACLOUD_COORDINATES: Record<string, { lat: number; lng: number }> = {
  // China regions
  "cn-hangzhou": { lat: 30.3, lng: 120.2 }, // Hangzhou
  "cn-shanghai": { lat: 31.2, lng: 121.5 }, // Shanghai
  "cn-beijing": { lat: 39.9, lng: 116.4 }, // Beijing
  "cn-shenzhen": { lat: 22.5, lng: 114.1 }, // Shenzhen
  "cn-zhangjiakou": { lat: 40.8, lng: 114.9 }, // Zhangjiakou
  "cn-huhehaote": { lat: 40.8, lng: 111.7 }, // Hohhot
  "cn-wulanchabu": { lat: 41.0, lng: 113.1 }, // Ulanqab
  "cn-chengdu": { lat: 30.7, lng: 104.1 }, // Chengdu
  "cn-qingdao": { lat: 36.1, lng: 120.4 }, // Qingdao
  "cn-nanjing": { lat: 32.1, lng: 118.8 }, // Nanjing
  "cn-fuzhou": { lat: 26.1, lng: 119.3 }, // Fuzhou
  "cn-guangzhou": { lat: 23.1, lng: 113.3 }, // Guangzhou
  "cn-heyuan": { lat: 23.7, lng: 114.7 }, // Heyuan
  "cn-hongkong": { lat: 22.3, lng: 114.2 }, // Hong Kong
  // Asia Pacific regions
  "ap-southeast-1": { lat: 1.4, lng: 103.8 }, // Singapore
  "ap-southeast-2": { lat: -33.9, lng: 151.2 }, // Sydney
  "ap-southeast-3": { lat: 3.1, lng: 101.7 }, // Kuala Lumpur
  "ap-southeast-5": { lat: -6.2, lng: 106.8 }, // Jakarta
  "ap-southeast-6": { lat: 13.8, lng: 100.5 }, // Bangkok
  "ap-southeast-7": { lat: 10.8, lng: 106.6 }, // Ho Chi Minh City
  "ap-northeast-1": { lat: 35.7, lng: 139.7 }, // Tokyo
  "ap-northeast-2": { lat: 37.6, lng: 127.0 }, // Seoul
  "ap-south-1": { lat: 19.1, lng: 72.9 }, // Mumbai
  // US & Europe regions
  "us-west-1": { lat: 37.4, lng: -121.9 }, // Silicon Valley
  "us-east-1": { lat: 39.0, lng: -77.5 }, // Virginia
  "eu-west-1": { lat: 51.5, lng: -0.1 }, // London
  "eu-central-1": { lat: 50.1, lng: 8.7 }, // Frankfurt
  // Middle East regions
  "me-east-1": { lat: 25.3, lng: 55.3 }, // Dubai
  "me-central-1": { lat: 24.5, lng: 54.4 }, // Riyadh
  global: { lat: 30.3, lng: 120.2 }, // Global fallback (Hangzhou HQ)
};

const PROVIDER_COORDINATES: Record<
  string,
  Record<string, { lat: number; lng: number }>
> = {
  aws: AWS_REGION_COORDINATES,
  azure: AZURE_REGION_COORDINATES,
  gcp: GCP_REGION_COORDINATES,
  google: GCP_REGION_COORDINATES, // Alias for gcp
  "google-cloud": GCP_REGION_COORDINATES, // Alternative naming
  kubernetes: KUBERNETES_COORDINATES,
  m365: M365_COORDINATES,
  github: GITHUB_COORDINATES,
  iac: IAC_COORDINATES,
  oraclecloud: ORACLECLOUD_COORDINATES,
  mongodbatlas: MONGODBATLAS_COORDINATES,
  alibabacloud: ALIBABACLOUD_COORDINATES,
};

// Returns [lng, lat] format for D3/GeoJSON compatibility
function getRegionCoordinates(
  providerType: string,
  region: string,
): [number, number] | null {
  const provider = providerType.toLowerCase();
  const providerCoords = PROVIDER_COORDINATES[provider];

  if (!providerCoords) return null;

  // Try to find specific region coordinates
  let coords = providerCoords[region.toLowerCase()];

  // For providers without traditional regions, fallback to "global"
  if (!coords && providerCoords["global"]) {
    coords = providerCoords["global"];
  }

  return coords ? [coords.lng, coords.lat] : null;
}

function getRiskLevel(failRate: number): RiskLevel {
  if (failRate >= 0.5) return RISK_LEVELS.CRITICAL;
  if (failRate >= 0.25) return RISK_LEVELS.HIGH;
  return RISK_LEVELS.LOW_HIGH;
}

// CSS variables are used for Recharts inline styles, not className
function buildSeverityData(fail: number, pass: number) {
  const total = fail + pass;
  const pct = (value: number) =>
    total > 0 ? Math.round((value / total) * 100) : 0;

  return [
    {
      name: "Fail",
      value: fail,
      percentage: pct(fail),
      color: "var(--color-bg-fail)",
    },
    {
      name: "Pass",
      value: pass,
      percentage: pct(pass),
      color: "var(--color-bg-pass)",
    },
  ];
}

// Formats "europe-west10" → "Europe West 10"
function formatRegionCode(region: string): string {
  return region
    .split(/[-_]/)
    .map((part) => {
      const match = part.match(/^([a-zA-Z]+)(\d+)$/);
      if (match) {
        const [, text, number] = match;
        return `${text.charAt(0).toUpperCase()}${text.slice(1).toLowerCase()} ${number}`;
      }
      return part.charAt(0).toUpperCase() + part.slice(1).toLowerCase();
    })
    .join(" ");
}

function formatRegionName(providerType: string, region: string): string {
  return `${getProviderDisplayName(providerType)} - ${formatRegionCode(region)}`;
}

/**
 * Adapts regions overview API response to threat map format.
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

    if (!coordinates) continue;

    // Add the actual region code to the set
    regionSet.add(attributes.region);

    const failRate =
      attributes.total > 0 ? attributes.fail / attributes.total : 0;

    locations.push({
      id,
      name: formatRegionName(attributes.provider_type, attributes.region),
      region: attributes.region, // Use actual region code for filtering
      regionCode: attributes.region,
      providerType: attributes.provider_type,
      coordinates,
      totalFindings: attributes.total,
      failFindings: attributes.fail,
      riskLevel: getRiskLevel(failRate),
      severityData: buildSeverityData(attributes.fail, attributes.pass),
    });
  }

  return {
    locations,
    regions: Array.from(regionSet).sort(),
  };
}
