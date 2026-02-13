import { LAYOUT_OPTIONS, SORT_OPTIONS } from "./shared/constants";

export type SortOption = (typeof SORT_OPTIONS)[keyof typeof SORT_OPTIONS];

export type LayoutOption = (typeof LAYOUT_OPTIONS)[keyof typeof LAYOUT_OPTIONS];

export interface BaseDataPoint {
  name: string;
  value: number;
  percentage?: number;
  color?: string;
  change?: number;
  newFindings?: number;
}

export interface BarDataPoint extends BaseDataPoint {}

export interface DonutDataPoint {
  name: string;
  value: number;
  color: string;
  percentage?: number;
  new?: number;
  muted?: number;
  change?: number;
}

export interface LineDataPoint {
  date: string;
  [key: string]: string | number | string[];
}

export interface RadarDataPoint {
  category: string;
  categoryId: string;
  value: number;
  change?: number;
  severityData?: BarDataPoint[];
}

export interface ScatterDataPoint {
  /** X-axis value (e.g., ThreatScore 0-100) */
  x: number;
  /** Y-axis value (e.g., Failed Findings count) */
  y: number;
  /** Provider type display name (AWS, Azure, Google Cloud, etc.) */
  provider: string;
  /** Display name (provider alias or identifier) */
  name: string;
  /** Optional provider ID for navigation/filtering */
  providerId?: string;
  /** Optional severity breakdown data for detail panel */
  severityData?: BarDataPoint[];
  /** Optional size for bubble chart variant */
  size?: number;
}

export interface LineConfig {
  dataKey: string;
  color: string;
  label: string;
}

export interface TooltipData {
  name: string;
  value: number | string;
  color?: string;
  percentage?: number;
  newFindings?: number;
  new?: number;
  muted?: number;
  change?: number;
  [key: string]: string | number | boolean | string[] | undefined;
}
