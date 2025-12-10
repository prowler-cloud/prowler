import { useSearchParams } from "next/navigation";
import { useEffect, useRef, useState } from "react";

import { useUrlFilters } from "@/hooks/use-url-filters";
import { isScanEntity } from "@/lib/helper-filters";
import {
  FilterEntity,
  FilterType,
  ProviderEntity,
  ProviderType,
  ScanEntity,
} from "@/types";

interface UseRelatedFiltersProps {
  providerIds?: string[];
  providerUIDs?: string[];
  providerDetails: { [key: string]: FilterEntity }[];
  completedScanIds?: string[];
  scanDetails?: { [key: string]: ScanEntity }[];
  enableScanRelation?: boolean;
  providerFilterType?: FilterType.PROVIDER | FilterType.PROVIDER_UID;
}

export const useRelatedFilters = ({
  providerIds = [],
  providerUIDs = [],
  providerDetails,
  completedScanIds = [],
  scanDetails = [],
  enableScanRelation = false,
  providerFilterType = FilterType.PROVIDER,
}: UseRelatedFiltersProps) => {
  const searchParams = useSearchParams();
  const { updateFilter } = useUrlFilters();
  const [availableScans, setAvailableScans] =
    useState<string[]>(completedScanIds);

  // Use providerIds if provided (for findings), otherwise use providerUIDs (for scans)
  const providers = providerIds.length > 0 ? providerIds : providerUIDs;
  const [availableProviders, setAvailableProviders] =
    useState<string[]>(providers);
  const previousProviders = useRef<string[]>([]);
  const previousProviderTypes = useRef<ProviderType[]>([]);
  const isManualDeselection = useRef(false);

  const getScanProvider = (scanId: string) => {
    if (!enableScanRelation) return null;
    const scanDetail = scanDetails.find(
      (detail) => Object.keys(detail)[0] === scanId,
    );
    return scanDetail ? scanDetail[scanId]?.providerInfo?.uid : null;
  };

  const getScanProviderType = (scanId: string): ProviderType | null => {
    if (!enableScanRelation) return null;
    const scanDetail = scanDetails.find(
      (detail) => Object.keys(detail)[0] === scanId,
    );
    return scanDetail ? scanDetail[scanId]?.providerInfo?.provider : null;
  };

  const getProviderType = (providerKey: string): ProviderType | null => {
    const providerDetail = providerDetails.find(
      (detail) => Object.keys(detail)[0] === providerKey,
    );
    if (!providerDetail) return null;

    const entity = providerDetail[providerKey];
    if (!isScanEntity(entity as ScanEntity)) {
      return (entity as ProviderEntity).provider;
    }
    return null;
  };

  useEffect(() => {
    const scanParam = enableScanRelation
      ? searchParams.get(`filter[${FilterType.SCAN}]`)
      : null;
    const providerParam = searchParams.get(`filter[${providerFilterType}]`);
    const providerTypeParam = searchParams.get(
      `filter[${FilterType.PROVIDER_TYPE}]`,
    );

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

    // Check if it's a manual deselection
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

    // Handle scan selection logic
    if (enableScanRelation && scanParam) {
      const scanProviderId = getScanProvider(scanParam);
      const scanProviderType = getScanProviderType(scanParam);

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
        updateFilter(FilterType.SCAN, null);
        // } else {
        //   // Add provider if not already selected
        //   if (scanProviderId && !currentProviders.includes(scanProviderId)) {
        //     updateFilter(FilterType.PROVIDER_UID, [
        //       ...currentProviders,
        //       scanProviderId,
        //     ]);
        //   }

        //   // Only add provider type if there are none selected
        //   if (
        //     scanProviderType &&
        //     currentProviderTypes.length === 0 &&
        //     !isManualDeselection.current
        //   ) {
        //     updateFilter(FilterType.PROVIDER_TYPE, [scanProviderType]);
        //   }
      }
    }

    // // Handle provider selection logic
    // if (
    //   currentProviders.length > 0 &&
    //   deselectedProviders.length === 0 &&
    //   !isManualDeselection.current
    // ) {
    //   const providerTypes = currentProviders
    //     .map(getProviderType)
    //     .filter((type): type is ProviderType => type !== null);
    //   const selectedProviderTypes = Array.from(new Set(providerTypes));

    //   if (
    //     selectedProviderTypes.length > 0 &&
    //     currentProviderTypes.length === 0
    //   ) {
    //     updateFilter(FilterType.PROVIDER_TYPE, selectedProviderTypes);
    //   }
    // }

    // Update available providers
    if (currentProviderTypes.length > 0) {
      const filteredProviders = providers.filter((key) => {
        const providerType = getProviderType(key);
        return providerType && currentProviderTypes.includes(providerType);
      });
      setAvailableProviders(filteredProviders);

      const validProviders = currentProviders.filter((key) => {
        const providerType = getProviderType(key);
        return providerType && currentProviderTypes.includes(providerType);
      });

      if (validProviders.length !== currentProviders.length) {
        updateFilter(
          providerFilterType,
          validProviders.length > 0 ? validProviders : null,
        );
      }
    } else {
      setAvailableProviders(providers);
    }

    // Update available scans
    if (enableScanRelation) {
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
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [searchParams]);

  return {
    availableProviderIds: providerIds.length > 0 ? availableProviders : [],
    availableProviderUIDs: providerUIDs.length > 0 ? availableProviders : [],
    availableScans,
  };
};
