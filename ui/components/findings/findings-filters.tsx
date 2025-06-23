"use client";

import { filterFindings } from "@/components/filters/data-filters";
import { FilterControls } from "@/components/filters/filter-controls";
import { useRelatedFilters } from "@/hooks";
import { FilterEntity, FilterType, ScanEntity, ScanProps } from "@/types";

interface FindingsFiltersProps {
  providerUIDs: string[];
  providerDetails: { [uid: string]: FilterEntity }[];
  completedScans: ScanProps[];
  completedScanIds: string[];
  scanDetails: { [key: string]: ScanEntity }[];
  uniqueRegions: string[];
  uniqueServices: string[];
  uniqueResourceTypes: string[];
}

export const FindingsFilters = ({
  providerUIDs,
  providerDetails,
  completedScanIds,
  scanDetails,
  uniqueRegions,
  uniqueServices,
  uniqueResourceTypes,
}: FindingsFiltersProps) => {
  const { availableProviderUIDs, availableScans } = useRelatedFilters({
    providerUIDs,
    providerDetails,
    completedScanIds,
    scanDetails,
    enableScanRelation: true,
  });

  return (
    <>
      <FilterControls
        search
        date
        customFilters={[
          ...filterFindings,
          {
            key: FilterType.PROVIDER_UID,
            labelCheckboxGroup: "Provider UID",
            values: availableProviderUIDs,
            valueLabelMapping: providerDetails,
            index: 6,
          },
          {
            key: FilterType.REGION,
            labelCheckboxGroup: "Regions",
            values: uniqueRegions,
            index: 3,
          },
          {
            key: FilterType.SERVICE,
            labelCheckboxGroup: "Services",
            values: uniqueServices,
            index: 4,
          },
          {
            key: FilterType.RESOURCE_TYPE,
            labelCheckboxGroup: "Resource Type",
            values: uniqueResourceTypes,
            index: 8,
          },
          {
            key: FilterType.SCAN,
            labelCheckboxGroup: "Scan ID",
            values: availableScans,
            valueLabelMapping: scanDetails,
            index: 7,
          },
        ]}
      />
    </>
  );
};
