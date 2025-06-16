"use client";

import { Spacer } from "@nextui-org/react";
import { useRouter, useSearchParams } from "next/navigation";
import React, { useEffect, useRef, useState } from "react";

import { filterFindings } from "@/components/filters/data-filters";
import { FilterControls } from "@/components/filters/filter-controls";
import { DataTableFilterCustom } from "@/components/ui/table";
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
  const router = useRouter();
  const searchParams = useSearchParams();
  const [updatedScanFilters, setUpdatedScanFilters] = useState<string[]>([]);
  const previousProviders = useRef<string[]>([]);

  // Function to get the provider of a scan
  const getScanProvider = (scanId: string) => {
    const scanDetail = scanDetails.find(
      (detail) => Object.keys(detail)[0] === scanId,
    );
    return scanDetail ? scanDetail[scanId]?.providerInfo?.uid : null;
  };

  // Function to update the URL with the new parameters
  const updateUrlParams = (updates: {
    scan?: string | null;
    provider?: string[] | null;
  }) => {
    const currentParams = new URLSearchParams(searchParams.toString());

    if (updates.scan === null) {
      currentParams.delete("filter[scan__in]");
    } else if (updates.scan !== undefined) {
      currentParams.set("filter[scan__in]", updates.scan);
    }

    if (updates.provider === null) {
      currentParams.delete("filter[provider_uid__in]");
    } else if (updates.provider !== undefined) {
      currentParams.set("filter[provider_uid__in]", updates.provider.join(","));
    }

    const newUrl = `${window.location.pathname}?${currentParams.toString()}`;
    router.push(newUrl);
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
        updateUrlParams({ scan: null });
        return; // Exit to avoid additional updates
      }
    }

    // When a new scan is selected
    if (scanParam && !deselectedProviders.length) {
      const scanProviderId = getScanProvider(scanParam);

      if (scanProviderId && !currentProviders.includes(scanProviderId)) {
        // Add the scan's provider to the list of selected providers
        updateUrlParams({ provider: [...currentProviders, scanProviderId] });
      }
    }

    // Update the list of scans based on the selected providers
    if (currentProviders.length > 0) {
      const filteredScans = scanDetails
        .filter((detail) => {
          const scanId = Object.keys(detail)[0];
          const scanInfo = detail[scanId];
          return currentProviders.includes(scanInfo?.providerInfo?.uid || "");
        })
        .map((detail) => Object.keys(detail)[0]);

      setUpdatedScanFilters(filteredScans);
    } else {
      setUpdatedScanFilters(completedScanIds);
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [searchParams, scanDetails, completedScanIds, router]);

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
            values: updatedScanFilters,
            valueLabelMapping: scanDetails,
            index: 9,
          },
        ]}
        defaultOpen={true}
      />
    </>
  );
};
