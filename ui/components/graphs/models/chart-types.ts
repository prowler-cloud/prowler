import { LAYOUT_OPTIONS, SORT_OPTIONS } from "../shared/chart-constants";

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
  [key: string]: string | number;
}

export interface RadarDataPoint {
  category: string;
  value: number;
  change?: number;
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
  [key: string]: any;
}
