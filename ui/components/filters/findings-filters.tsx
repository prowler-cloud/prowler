"use client";

import { Spacer } from "@nextui-org/react";
import { useSearchParams } from "next/navigation";
import { useEffect, useRef, useState } from "react";

import { filterFindings } from "@/components/filters/data-filters";
import { FilterControls } from "@/components/filters/filter-controls";
import { DataTableFilterCustom } from "@/components/ui/table";
import { useUrlFilters } from "@/hooks/use-url-filters";
import { isScanEntity } from "@/lib/helper-filters";
import {
  FilterEntity,
  ProviderEntity,
  ProviderType,
  ScanEntity,
  ScanProps,
} from "@/types";

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
  const [availableProviderUIDs, setAvailableProviderUIDs] =
    useState<string[]>(providerUIDs);
  const previousProviders = useRef<string[]>([]);
  const previousProviderTypes = useRef<ProviderType[]>([]);
  const isManualDeselection = useRef(false);

  // Helper functions for getting provider and scan information
  const getScanProvider = (scanId: string) => {
    const scanDetail = scanDetails.find(
      (detail) => Object.keys(detail)[0] === scanId,
    );
    return scanDetail ? scanDetail[scanId]?.providerInfo?.uid : null;
  };

  const getScanProviderType = (scanId: string): ProviderType | null => {
    const scanDetail = scanDetails.find(
      (detail) => Object.keys(detail)[0] === scanId,
    );
    return scanDetail ? scanDetail[scanId]?.providerInfo?.provider : null;
  };

  const getProviderType = (providerUid: string): ProviderType | null => {
    const providerDetail = providerDetails.find(
      (detail) => Object.keys(detail)[0] === providerUid,
    );
    if (!providerDetail) return null;

    const entity = providerDetail[providerUid];
    if (!isScanEntity(entity as ScanEntity)) {
      return (entity as ProviderEntity).provider;
    }
    return null;
  };

  // Functions to handle different filter updates
  const handleScanSelection = (
    scanParam: string | null,
    currentProviders: string[],
    currentProviderTypes: ProviderType[],
    deselectedProviders: string[],
    deselectedProviderTypes: ProviderType[],
  ) => {
    if (!scanParam) return;

    const scanProviderId = getScanProvider(scanParam);
    const scanProviderType = getScanProviderType(scanParam);

    // Check if scan should be deselected - but ignore provider type deselection if it's manual
    const shouldDeselectScan =
      (scanProviderId &&
        (deselectedProviders.includes(scanProviderId) ||
          (currentProviders.length > 0 &&
            !currentProviders.includes(scanProviderId)))) ||
      (scanProviderType &&
        !isManualDeselection.current &&
        (deselectedProviderTypes.includes(scanProviderType) ||
          (currentProviderTypes.length > 0 &&
            !currentProviderTypes.includes(scanProviderType))));

    if (shouldDeselectScan) {
      updateFilter("scan__in", null);
      return;
    }

    // Add provider if not already selected
    if (scanProviderId && !currentProviders.includes(scanProviderId)) {
      updateFilter("provider_uid__in", [...currentProviders, scanProviderId]);
    }

    // Only add provider type if there are none selected and it's not a manual deselection
    if (
      scanProviderType &&
      currentProviderTypes.length === 0 &&
      !isManualDeselection.current
    ) {
      updateFilter("provider_type__in", [scanProviderType]);
    }
  };

  const handleProviderSelection = (
    currentProviders: string[],
    currentProviderTypes: ProviderType[],
    deselectedProviders: string[],
  ) => {
    // No hacer nada si es una deselección manual o no hay providers seleccionados
    if (
      currentProviders.length === 0 ||
      deselectedProviders.length > 0 ||
      isManualDeselection.current
    )
      return;

    // Get unique provider types from selected providers
    const providerTypes = currentProviders
      .map(getProviderType)
      .filter((type): type is ProviderType => type !== null);
    const selectedProviderTypes = Array.from(new Set(providerTypes));

    // Only add provider types if there are none selected
    if (selectedProviderTypes.length > 0 && currentProviderTypes.length === 0) {
      updateFilter("provider_type__in", selectedProviderTypes);
    }
  };

  const updateAvailableProviders = (
    currentProviderTypes: ProviderType[],
    currentProviders: string[],
  ) => {
    if (currentProviderTypes.length > 0) {
      // Filter available provider UIDs
      const filteredProviderUIDs = providerUIDs.filter((uid) => {
        const providerType = getProviderType(uid);
        return providerType && currentProviderTypes.includes(providerType);
      });
      setAvailableProviderUIDs(filteredProviderUIDs);

      // Handle selected providers that don't match current types
      const validProviders = currentProviders.filter((uid) => {
        const providerType = getProviderType(uid);
        return providerType && currentProviderTypes.includes(providerType);
      });

      if (validProviders.length !== currentProviders.length) {
        updateFilter(
          "provider_uid__in",
          validProviders.length > 0 ? validProviders : null,
        );
      }
    } else {
      setAvailableProviderUIDs(providerUIDs);
    }
  };

  const updateAvailableScans = (
    currentProviders: string[],
    currentProviderTypes: ProviderType[],
  ) => {
    if (currentProviders.length > 0 || currentProviderTypes.length > 0) {
      const filteredScans = completedScanIds.filter((scanId) => {
        const scanProviderId = getScanProvider(scanId);
        const scanProviderType = getScanProviderType(scanId);

        return (
          (currentProviders.length === 0 ||
            (scanProviderId && currentProviders.includes(scanProviderId))) &&
          (currentProviderTypes.length === 0 ||
            (scanProviderType &&
              currentProviderTypes.includes(scanProviderType)))
        );
      });
      setAvailableScans(filteredScans);
    } else {
      setAvailableScans(completedScanIds);
    }
  };

  useEffect(() => {
    // Extract current filter values
    const scanParam = searchParams.get("filter[scan__in]");
    const providerParam = searchParams.get("filter[provider_uid__in]");
    const providerTypeParam = searchParams.get("filter[provider_type__in]");

    const currentProviders = providerParam ? providerParam.split(",") : [];
    const currentProviderTypes = providerTypeParam
      ? (providerTypeParam.split(",") as ProviderType[])
      : [];

    // Detect deselected items
    const deselectedProviders = previousProviders.current.filter(
      (provider) => !currentProviders.includes(provider),
    );
    const deselectedProviderTypes = previousProviderTypes.current.filter(
      (type) => !currentProviderTypes.includes(type),
    );

    // Check if it's a manual deselection of provider types
    if (deselectedProviderTypes.length > 0) {
      isManualDeselection.current = true;
    } else if (
      currentProviderTypes.length === 0 &&
      previousProviderTypes.current.length === 0
    ) {
      isManualDeselection.current = false;
    }

    // Update references
    previousProviders.current = currentProviders;
    previousProviderTypes.current = currentProviderTypes;

    // Handle different filter updates
    handleScanSelection(
      scanParam,
      currentProviders,
      currentProviderTypes,
      deselectedProviders,
      deselectedProviderTypes,
    );
    handleProviderSelection(
      currentProviders,
      currentProviderTypes,
      deselectedProviders,
    );
    updateAvailableProviders(currentProviderTypes, currentProviders);
    updateAvailableScans(currentProviders, currentProviderTypes);
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
            values: availableProviderUIDs,
            valueLabelMapping: providerDetails,
            index: 6,
          },
          {
            key: "region__in",
            labelCheckboxGroup: "Regions",
            values: uniqueRegions,
            index: 3,
          },
          {
            key: "service__in",
            labelCheckboxGroup: "Services",
            values: uniqueServices,
            index: 4,
          },
          {
            key: "resource_type__in",
            labelCheckboxGroup: "Resource Type",
            values: uniqueResourceTypes,
            index: 8,
          },
          {
            key: "scan__in",
            labelCheckboxGroup: "Scan ID",
            values: availableScans,
            valueLabelMapping: scanDetails,
            index: 7,
          },
        ]}
        defaultOpen={true}
      />
    </>
  );
};
