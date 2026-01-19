// GET /api/v1/overviews/resource-groups endpoint

interface OverviewResponseMeta {
  version: string;
}

export interface SeverityBreakdown {
  informational: number;
  low: number;
  medium: number;
  high: number;
  critical: number;
}

export interface ResourceGroupOverviewAttributes {
  id: string;
  total_findings: number;
  failed_findings: number;
  new_failed_findings: number;
  resources_count: number;
  severity: SeverityBreakdown;
}

export interface ResourceGroupOverview {
  type: "resource-group-overview";
  id: string;
  attributes: ResourceGroupOverviewAttributes;
}

export interface ResourceGroupOverviewResponse {
  data: ResourceGroupOverview[];
  meta: OverviewResponseMeta;
}
