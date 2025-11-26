// Providers Overview Types
// Corresponds to the /overviews/providers endpoint

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
  meta: {
    version: string;
  };
}

// Services Overview Types
// Corresponds to the /overviews/services endpoint

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
  meta: {
    version: string;
  };
}

// ThreatScore Snapshot Types
// Corresponds to the ThreatScoreSnapshot model from the API

export interface CriticalRequirement {
  requirement_id: string;
  risk_level: number;
  weight: number;
  title: string;
}

export type SectionScores = Record<string, number>;

export interface ThreatScoreSnapshotAttributes {
  id: string;
  inserted_at: string;
  scan: string | null;
  provider: string | null;
  compliance_id: string;
  overall_score: string;
  score_delta: string | null;
  section_scores: SectionScores;
  critical_requirements: CriticalRequirement[];
  total_requirements: number;
  passed_requirements: number;
  failed_requirements: number;
  manual_requirements: number;
  total_findings: number;
  passed_findings: number;
  failed_findings: number;
}

export interface ThreatScoreSnapshot {
  id: string;
  type: "threatscore-snapshots";
  attributes: ThreatScoreSnapshotAttributes;
}

export interface ThreatScoreResponse {
  data: ThreatScoreSnapshot[];
}

// Findings Severity Overview Types
// Corresponds to the /overviews/findings_severity endpoint

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
  meta: {
    version: string;
  };
}

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

// Filters for ThreatScore endpoint
export interface ThreatScoreFilters {
  snapshot_id?: string;
  provider_id?: string;
  provider_id__in?: string;
  provider_type?: string;
  provider_type__in?: string;
  scan_id?: string;
  scan_id__in?: string;
  compliance_id?: string;
  compliance_id__in?: string;
  inserted_at?: string;
  inserted_at__gte?: string;
  inserted_at__lte?: string;
  overall_score__gte?: string;
  overall_score__lte?: string;
}
