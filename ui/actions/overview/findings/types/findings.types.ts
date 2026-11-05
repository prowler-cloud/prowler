// Findings Severity Overview Types
// Corresponds to the /overviews/findings_severity endpoint

interface OverviewResponseMeta {
  version: string;
}

// Corresponds to the /overviews/findings endpoint (OverviewFindingSerializer)
export interface FindingsStatusAttributes {
  new: number;
  changed: number;
  unchanged: number;
  fail_new: number;
  fail_changed: number;
  pass_new: number;
  pass_changed: number;
  muted_new: number;
  muted_changed: number;
  total: number;
  pass: number;
  fail: number;
  muted: number;
}

export interface FindingsStatusOverview {
  type: "findings-overview";
  id: string;
  attributes: FindingsStatusAttributes;
}

export interface FindingsStatusOverviewResponse {
  data: FindingsStatusOverview;
  meta: OverviewResponseMeta;
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
