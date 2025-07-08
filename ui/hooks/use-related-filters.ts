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
  providerUIDs: string[];
  providerDetails: { [uid: string]: FilterEntity }[];
  completedScanIds?: string[];
  scanDetails?: { [key: string]: ScanEntity }[];
  enableScanRelation?: boolean;
}

export const useRelatedFilters = ({
  providerUIDs,
  providerDetails,
  completedScanIds = [],
  scanDetails = [],
  enableScanRelation = false,
}: UseRelatedFiltersProps) => {
  const searchParams = useSearchParams();
  const { updateFilter } = useUrlFilters();
  const [availableScans, setAvailableScans] =
    useState<string[]>(completedScanIds);
  const [availableProviderUIDs, setAvailableProviderUIDs] =
    useState<string[]>(providerUIDs);
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
    const scanParam = enableScanRelation
      ? searchParams.get(`filter[${FilterType.SCAN}]`)
      : null;
    const providerParam = searchParams.get(
      `filter[${FilterType.PROVIDER_UID}]`,
    );
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
      const filteredProviderUIDs = providerUIDs.filter((uid) => {
        const providerType = getProviderType(uid);
        return providerType && currentProviderTypes.includes(providerType);
      });
      setAvailableProviderUIDs(filteredProviderUIDs);

      const validProviders = currentProviders.filter((uid) => {
        const providerType = getProviderType(uid);
        return providerType && currentProviderTypes.includes(providerType);
      });

      if (validProviders.length !== currentProviders.length) {
        updateFilter(
          FilterType.PROVIDER_UID,
          validProviders.length > 0 ? validProviders : null,
        );
      }
    } else {
      setAvailableProviderUIDs(providerUIDs);
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
    availableProviderUIDs,
    availableScans,
  };
};
