import { ProviderEntity } from "./providers";
import { ScanEntity } from "./scans";

export type FilterEntity = ProviderEntity | ScanEntity;

export interface FilterOption {
  key: string;
  labelCheckboxGroup: string;
  values: string[];
  valueLabelMapping?: Array<{ [uid: string]: FilterEntity }>;
  index?: number;
  showSelectAll?: boolean;
  defaultToSelectAll?: boolean;
  defaultValues?: string[];
}

export interface CustomDropdownFilterProps {
  filter: FilterOption;
  onFilterChange: (key: string, values: string[]) => void;
}

export interface FilterControlsProps {
  search?: boolean;
  providers?: boolean;
  date?: boolean;
  regions?: boolean;
  accounts?: boolean;
  mutedFindings?: boolean;
  customFilters?: FilterOption[];
}

export enum FilterType {
  SCAN = "scan__in",
  PROVIDER_UID = "provider_uid__in",
  PROVIDER_TYPE = "provider_type__in",
  REGION = "region__in",
  SERVICE = "service__in",
  RESOURCE_TYPE = "resource_type__in",
  SEVERITY = "severity__in",
  STATUS = "status__in",
  DELTA = "delta__in",
}
