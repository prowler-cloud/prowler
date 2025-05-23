import { ProviderType } from "./providers";

export interface FilterOption {
  key: string;
  labelCheckboxGroup: string;
  values: string[];
  valueLabelMapping?: Array<{
    [uid: string]: {
      providerInfo: {
        provider: ProviderType;
        alias?: string;
        uid?: string;
      };
      attributes: {
        name?: string;
        completed_at: string;
      };
    };
  }>;
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
