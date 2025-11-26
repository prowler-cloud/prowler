// Regions Overview Types
// Corresponds to the /overviews/regions endpoint

export interface RegionOverviewAttributes {
  provider_type: string;
  region: string;
  total: number;
  fail: number;
  muted: number;
  pass: number;
}

export interface RegionOverview {
  type: "regions-overview";
  id: string;
  attributes: RegionOverviewAttributes;
}

export interface RegionsOverviewResponse {
  data: RegionOverview[];
  meta: {
    version: string;
  };
}
