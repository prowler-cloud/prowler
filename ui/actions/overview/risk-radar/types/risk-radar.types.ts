// Category Overview Types
// Corresponds to the /overviews/categories endpoint

interface OverviewResponseMeta {
  version: string;
}

export interface CategorySeverity {
  informational: number;
  low: number;
  medium: number;
  high: number;
  critical: number;
}

export interface CategoryOverviewAttributes {
  total_findings: number;
  failed_findings: number;
  new_failed_findings: number;
  severity: CategorySeverity;
}

export interface CategoryOverview {
  type: "category-overviews";
  id: string;
  attributes: CategoryOverviewAttributes;
}

export interface CategoryOverviewResponse {
  data: CategoryOverview[];
  meta: OverviewResponseMeta;
}
