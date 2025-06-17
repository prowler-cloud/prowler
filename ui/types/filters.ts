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
