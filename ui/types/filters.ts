export interface FilterOption {
  key: string;
  labelCheckboxGroup: string;
  values: string[];
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
