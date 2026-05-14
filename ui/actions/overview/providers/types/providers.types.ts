// Providers Overview Types
// Corresponds to the /overviews/providers endpoint

interface OverviewResponseMeta {
  version: string;
}

export interface ProviderOverviewFindings {
  pass: number;
  fail: number;
  muted: number;
  total: number;
}

export interface ProviderOverviewResources {
  total: number;
}

export interface ProviderOverviewAttributes {
  findings: ProviderOverviewFindings;
  resources: ProviderOverviewResources;
}

export interface ProviderOverview {
  type: "providers-overview";
  id: string;
  attributes: ProviderOverviewAttributes;
}

export interface ProvidersOverviewResponse {
  data: ProviderOverview[];
  meta: OverviewResponseMeta;
}
