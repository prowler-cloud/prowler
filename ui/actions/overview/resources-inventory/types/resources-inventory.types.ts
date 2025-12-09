// /overviews/resources-types endpoint

interface OverviewResponseMeta {
  version: string;
}

export interface ResourcesInventoryOverviewAttributes {
  total_resources: number;
  failed_findings: number;
  new_findings: number;
  misconfigurations: number;
}

export interface ResourcesInventoryOverview {
  type: "resources-inventory-overviews";
  id: string;
  attributes: ResourcesInventoryOverviewAttributes;
}

export interface ResourcesInventoryOverviewResponse {
  data: ResourcesInventoryOverview[];
  meta: OverviewResponseMeta;
}
