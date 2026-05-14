// Services Overview Types
// Corresponds to the /overviews/services endpoint

interface OverviewResponseMeta {
  version: string;
}

export interface ServiceOverviewAttributes {
  total: number;
  fail: number;
  muted: number;
  pass: number;
}

export interface ServiceOverview {
  type: "services-overview";
  id: string;
  attributes: ServiceOverviewAttributes;
}

export interface ServicesOverviewResponse {
  data: ServiceOverview[];
  meta: OverviewResponseMeta;
}
