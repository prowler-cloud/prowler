import { CloudProviders } from "./components";
export interface ProviderAttributes {
  provider: CloudProviders;
  uid: string;
  alias: string;
}
export interface FilterOption {
  key: string;
  labelCheckboxGroup: string;
  values: string[];
  valueLabelMapping?: Array<{ [uid: string]: ProviderAttributes }>;
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
