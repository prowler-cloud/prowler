"use client";

import { filterScans } from "@/components/filters/data-filters";
import { FilterControls } from "@/components/filters/filter-controls";
import { useRelatedFilters } from "@/hooks";
import { FilterEntity, FilterType } from "@/types";

interface ScansFiltersProps {
  providerUIDs: string[];
  providerDetails: { [uid: string]: FilterEntity }[];
}

export const ScansFilters = ({
  providerUIDs,
  providerDetails,
}: ScansFiltersProps) => {
  const { availableProviderUIDs } = useRelatedFilters({
    providerUIDs,
    providerDetails,
    enableScanRelation: false,
    providerFilterType: FilterType.PROVIDER_UID,
  });

  return (
    <FilterControls
      customFilters={[
        ...filterScans,
        {
          key: FilterType.PROVIDER_UID,
          labelCheckboxGroup: "Provider UID",
          values: availableProviderUIDs,
          valueLabelMapping: providerDetails,
          index: 1,
        },
      ]}
    />
  );
};
