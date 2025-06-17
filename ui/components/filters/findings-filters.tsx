"use client";

import { Spacer } from "@nextui-org/react";
import { useSearchParams } from "next/navigation";
import React, { useEffect, useRef, useState } from "react";

import { filterFindings } from "@/components/filters/data-filters";
import { FilterControls } from "@/components/filters/filter-controls";
import { DataTableFilterCustom } from "@/components/ui/table";
import { useUrlFilters } from "@/hooks/use-url-filters";
import { FilterEntity, ScanEntity } from "@/types";
import { ScanProps } from "@/types";

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
  const searchParams = useSearchParams();
  const { updateFilter } = useUrlFilters();
  const [availableScans, setAvailableScans] =
    useState<string[]>(completedScanIds);
  const previousProviders = useRef<string[]>([]);

  const getScanProvider = (scanId: string) => {
    const scanDetail = scanDetails.find(
      (detail) => Object.keys(detail)[0] === scanId,
    );
    return scanDetail ? scanDetail[scanId]?.providerInfo?.uid : null;
  };

  useEffect(() => {
    const scanParam = searchParams.get("filter[scan__in]");
    const providerParam = searchParams.get("filter[provider_uid__in]");
    const currentProviders = providerParam ? providerParam.split(",") : [];

    // Detect deselected providers
    const deselectedProviders = previousProviders.current.filter(
      (provider) => !currentProviders.includes(provider),
    );

    // Update the reference of providers
    previousProviders.current = currentProviders;

    // If there is a scan selected, check if its provider was deselected
    if (scanParam) {
      const scanProviderId = getScanProvider(scanParam);

      // If the scan's provider was deselected or is no longer in the list of selected providers
      if (
        scanProviderId &&
        (deselectedProviders.includes(scanProviderId) ||
          (currentProviders.length > 0 &&
            !currentProviders.includes(scanProviderId)))
      ) {
        // Deselect the scan
        updateFilter("scan__in", null);
        return; // Exit to avoid additional updates
      }
    }

    // When a new scan is selected
    if (scanParam && !deselectedProviders.length) {
      const scanProviderId = getScanProvider(scanParam);

      if (scanProviderId && !currentProviders.includes(scanProviderId)) {
        // Add the scan's provider to the list of selected providers
        updateFilter("provider_uid__in", [...currentProviders, scanProviderId]);
      }
    }

    // Update available scans based on selected providers
    if (currentProviders.length > 0) {
      // Filter scans that belong to any of the selected providers
      const filteredScans = completedScanIds.filter((scanId) => {
        const scanProviderId = getScanProvider(scanId);
        return scanProviderId && currentProviders.includes(scanProviderId);
      });
      setAvailableScans(filteredScans);
    } else {
      // If no providers selected, show all completed scans
      setAvailableScans(completedScanIds);
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [searchParams, scanDetails, completedScanIds, updateFilter]);

  return (
    <>
      <FilterControls search date />
      <Spacer y={8} />
      <DataTableFilterCustom
        filters={[
          ...filterFindings,
          {
            key: "provider_uid__in",
            labelCheckboxGroup: "Provider UID",
            values: providerUIDs,
            valueLabelMapping: providerDetails,
            index: 5,
          },
          {
            key: "region__in",
            labelCheckboxGroup: "Regions",
            values: uniqueRegions,
            index: 5,
          },
          {
            key: "service__in",
            labelCheckboxGroup: "Services",
            values: uniqueServices,
            index: 6,
          },
          {
            key: "resource_type__in",
            labelCheckboxGroup: "Resource Type",
            values: uniqueResourceTypes,
            index: 7,
          },
          {
            key: "scan__in",
            labelCheckboxGroup: "Scan ID",
            values: availableScans,
            valueLabelMapping: scanDetails,
            index: 9,
          },
        ]}
        defaultOpen={true}
      />
    </>
  );
};
