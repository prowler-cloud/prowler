// Findings Severity Overview Types
// Corresponds to the /overviews/findings_severity endpoint

interface OverviewResponseMeta {
  version: string;
}

export interface FindingsSeverityAttributes {
  critical: number;
  high: number;
  medium: number;
  low: number;
  informational: number;
}

export interface FindingsSeverityOverview {
  type: "findings-severity-overview";
  id: string;
  attributes: FindingsSeverityAttributes;
}

export interface FindingsSeverityOverviewResponse {
  data: FindingsSeverityOverview;
  meta: OverviewResponseMeta;
}
