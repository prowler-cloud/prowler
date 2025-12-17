// THREATSCORE Snapshot Types
// Corresponds to the THREATSCORESnapshot model from the API

export interface CriticalRequirement {
  requirement_id: string;
  risk_level: number;
  weight: number;
  title: string;
}

export type SectionScores = Record<string, number>;

export interface THREATSCORESnapshotAttributes {
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

export interface THREATSCORESnapshot {
  id: string;
  type: "THREATSCORE-snapshots";
  attributes: THREATSCORESnapshotAttributes;
}

export interface THREATSCOREResponse {
  data: THREATSCORESnapshot[];
}

// Filters for THREATSCORE endpoint
export interface THREATSCOREFilters {
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
