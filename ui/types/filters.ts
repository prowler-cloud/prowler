import {
  GroupFilterEntity,
  ProviderConnectionStatus,
  ProviderEntity,
} from "./providers";
import { ScanEntity } from "./scans";

export type FilterEntity =
  | ProviderEntity
  | ScanEntity
  | ProviderConnectionStatus
  | GroupFilterEntity;

export interface FilterOption {
  key: string;
  labelCheckboxGroup: string;
  values: string[];
  valueLabelMapping?: Array<{ [uid: string]: FilterEntity }>;
  labelFormatter?: (value: string) => string;
  index?: number;
  showSelectAll?: boolean;
  defaultToSelectAll?: boolean;
  defaultValues?: string[];
}

export interface CustomDropdownFilterProps {
  filter: FilterOption;
  onFilterChange: (key: string, values: string[]) => void;
}

export enum FilterType {
  SCAN = "scan__in",
  PROVIDER = "provider__in",
  PROVIDER_UID = "provider_uid__in",
  PROVIDER_TYPE = "provider_type__in",
  REGION = "region__in",
  SERVICE = "service__in",
  RESOURCE_TYPE = "resource_type__in",
  SEVERITY = "severity__in",
  STATUS = "status__in",
  DELTA = "delta__in",
  CATEGORY = "category__in",
  RESOURCE_GROUPS = "resource_groups__in",
}

/**
 * Controls the filter dispatch behavior of DataTableFilterCustom.
 * - "instant": every selection immediately updates the URL (legacy/default behavior)
 * - "batch":   selections accumulate in pending state; URL only updates on explicit apply
 */
export const DATA_TABLE_FILTER_MODE = {
  INSTANT: "instant",
  BATCH: "batch",
} as const;

export type DataTableFilterMode =
  (typeof DATA_TABLE_FILTER_MODE)[keyof typeof DATA_TABLE_FILTER_MODE];
