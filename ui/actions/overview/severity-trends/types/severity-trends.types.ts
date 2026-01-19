import { LineDataPoint } from "@/components/graphs/types";

// API Response Types (what comes from the backend)
export interface FindingsSeverityOverTimeAttributes {
  critical: number;
  high: number;
  medium: number;
  low: number;
  informational: number;
  muted: number;
  scan_ids: string[];
}

export interface FindingsSeverityOverTimeItem {
  type: "findings-severity-over-time";
  id: string;
  attributes: FindingsSeverityOverTimeAttributes;
}

export interface FindingsSeverityOverTimeMeta {
  version: string;
}

export interface FindingsSeverityOverTimeResponse {
  data: FindingsSeverityOverTimeItem[];
  meta: FindingsSeverityOverTimeMeta;
}

// Adapted Types (what the UI components expect)
export interface AdaptedSeverityTrendsResponse {
  data: LineDataPoint[];
  meta: FindingsSeverityOverTimeMeta;
}
