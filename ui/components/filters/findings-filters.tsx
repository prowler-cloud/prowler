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

  useEffect(() => {
    const scanParam = searchParams.get("filter[scan__in]");
    const providerParam = searchParams.get("filter[provider_uid__in]");
    const providerTypeParam = searchParams.get("filter[provider_type__in]");

    const currentProviders = providerParam ? providerParam.split(",") : [];
    const currentProviderTypes = providerTypeParam
      ? (providerTypeParam.split(",") as ProviderType[])
      : [];

    // Detect deselected providers and provider types
    const deselectedProviders = previousProviders.current.filter(
      (provider) => !currentProviders.includes(provider),
    );
    const deselectedProviderTypes = previousProviderTypes.current.filter(
      (type) => !currentProviderTypes.includes(type),
    );

    // Update the reference of providers and provider types
    previousProviders.current = currentProviders;
    previousProviderTypes.current = currentProviderTypes;

    // Handle scan selection
    if (scanParam) {
      const scanProviderId = getScanProvider(scanParam);
      const scanProviderType = getScanProviderType(scanParam);

      // If the scan's provider was deselected or its type was deselected
      if (
        (scanProviderId &&
          (deselectedProviders.includes(scanProviderId) ||
            (currentProviders.length > 0 &&
              !currentProviders.includes(scanProviderId)))) ||
        (scanProviderType &&
          (deselectedProviderTypes.includes(scanProviderType) ||
            (currentProviderTypes.length > 0 &&
              !currentProviderTypes.includes(scanProviderType))))
      ) {
        // Deselect the scan
        updateFilter("scan__in", null);
        return;
      }

      // Add provider and provider type if not already selected
      if (scanProviderId && !currentProviders.includes(scanProviderId)) {
        updateFilter("provider_uid__in", [...currentProviders, scanProviderId]);
      }
      if (
        scanProviderType &&
        !currentProviderTypes.includes(scanProviderType)
      ) {
        updateFilter("provider_type__in", [
          ...currentProviderTypes,
          scanProviderType,
        ]);
      }
    }

    // Handle provider selection
    if (currentProviders.length > 0 && !deselectedProviders.length) {
      // Get unique provider types from selected providers
      const providerTypes = currentProviders
        .map(getProviderType)
        .filter((type): type is ProviderType => type !== null);
      const selectedProviderTypes = Array.from(new Set(providerTypes));

      // Update provider types if different from current selection
      if (selectedProviderTypes.length > 0) {
        const newTypes = selectedProviderTypes.filter(
          (type) => !currentProviderTypes.includes(type),
        );
        if (newTypes.length > 0) {
          updateFilter("provider_type__in", [
            ...currentProviderTypes,
            ...newTypes,
          ]);
        }
      }
    }

    // Update available provider UIDs based on selected provider types
    if (currentProviderTypes.length > 0) {
      const filteredProviderUIDs = providerUIDs.filter((uid) => {
        const providerType = getProviderType(uid);
        return providerType && currentProviderTypes.includes(providerType);
      });
      setAvailableProviderUIDs(filteredProviderUIDs);

      // If there are selected providers that don't match the current provider types, deselect them
      if (currentProviders.length > 0) {
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
      }
    } else {
      setAvailableProviderUIDs(providerUIDs);
    }

    // Update available scans based on selected providers and provider types
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
