import { BarDataPoint } from "./types";

export const MAP_CONFIG = {
  defaultWidth: 688,
  defaultHeight: 400,
  pointRadius: 6,
  selectedPointRadius: 8,
  transitionDuration: 300,
} as const;

export const RISK_LEVELS = {
  LOW_HIGH: "low-high",
  HIGH: "high",
  CRITICAL: "critical",
} as const;

export type RiskLevel = (typeof RISK_LEVELS)[keyof typeof RISK_LEVELS];

export interface LocationPoint {
  id: string;
  name: string;
  region: string;
  regionCode: string;
  providerType: string;
  coordinates: [number, number];
  totalFindings: number;
  failFindings: number;
  riskLevel: RiskLevel;
  severityData: BarDataPoint[];
  change?: number;
}

export interface ThreatMapData {
  locations: LocationPoint[];
  regions: string[];
}

export interface ThreatMapProps {
  data: ThreatMapData;
  height?: number;
  onLocationSelect?: (location: LocationPoint | null) => void;
}

export interface MapColorsConfig {
  landFill: string;
  landStroke: string;
  pointDefault: string;
  pointSelected: string;
  pointHover: string;
}

// SVG fill/stroke attributes require actual color values, not Tailwind classes
// These hex fallbacks are used during SSR when CSS variables aren't available
// At runtime, getMapColors() retrieves computed CSS variable values
export const DEFAULT_MAP_COLORS: MapColorsConfig = {
  landFill: "#d1d5db", // --bg-neutral-map fallback
  landStroke: "#cbd5e1", // --border-neutral-tertiary fallback
  pointDefault: "#dc2626", // --text-text-error fallback
  pointSelected: "#10b981", // --bg-button-primary fallback
  pointHover: "#dc2626", // --text-text-error fallback
};

export const STATUS_FILTER_MAP: Record<string, string> = {
  Fail: "FAIL",
  Pass: "PASS",
};
