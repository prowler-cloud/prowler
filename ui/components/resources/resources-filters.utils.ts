import type { FilterChip } from "@/components/filters/filter-summary-strip";
import { formatLabel, getGroupLabel } from "@/lib/categories";
import type { ProviderProps } from "@/types/providers";
import { getProviderDisplayName } from "@/types/providers";

const RESOURCE_FILTER_KEY_LABELS: Record<string, string> = {
  "filter[provider_type__in]": "Provider",
  "filter[provider_id__in]": "Account",
  "filter[region__in]": "Region",
  "filter[service__in]": "Service",
  "filter[type__in]": "Type",
  "filter[groups__in]": "Group",
};

function getProviderAccountDisplayValue(
  providerId: string,
  providers: ProviderProps[],
): string {
  const provider = providers.find((item) => item.id === providerId);
  if (!provider) {
    return providerId;
  }

  return provider.attributes.alias || provider.attributes.uid || providerId;
}

export function getResourcesFilterDisplayValue(
  filterKey: string,
  value: string,
  providers: ProviderProps[],
): string {
  if (!value) return value;

  if (filterKey === "filter[provider_type__in]") {
    return getProviderDisplayName(value);
  }

  if (filterKey === "filter[provider_id__in]") {
    return getProviderAccountDisplayValue(value, providers);
  }

  if (filterKey === "filter[groups__in]") {
    return getGroupLabel(value);
  }

  if (filterKey === "filter[type__in]") {
    return formatLabel(value, "_");
  }

  return value;
}

export function buildResourcesFilterChips(
  pendingFilters: Record<string, string[]>,
  providers: ProviderProps[],
): FilterChip[] {
  const chips: FilterChip[] = [];

  Object.entries(pendingFilters).forEach(([key, values]) => {
    if (!values || values.length === 0) return;

    const label = RESOURCE_FILTER_KEY_LABELS[key] ?? key;
    const displayValues = values.map((value) =>
      getResourcesFilterDisplayValue(key, value, providers),
    );

    const chip: FilterChip = {
      key,
      label,
      value: values[0],
      displayValue:
        displayValues.length > 1
          ? `+${displayValues.length}`
          : displayValues[0],
    };

    if (values.length > 1) {
      chip.values = values;
      chip.displayValues = displayValues;
    }

    chips.push(chip);
  });

  return chips;
}
