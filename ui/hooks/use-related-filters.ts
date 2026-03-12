import { useSearchParams } from "next/navigation";

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

/**
 * Derives available providers and scans based on the current URL filters.
 *
 * Pure computation — no effects, no state, no navigation. The returned
 * lists update automatically when searchParams change because the component
 * re-renders with new searchParams from Next.js.
 *
 * Cascading filter cleanup (e.g. auto-clearing a scan when its provider is
 * deselected) is handled atomically by the filter components themselves
 * (ProviderTypeSelector clears provider_id__in, AccountsSelector updates
 * provider_type__in). This avoids the production bug where router.push()
 * calls inside useEffect would silently abort pending navigations.
 */
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

  const providers = providerIds.length > 0 ? providerIds : providerUIDs;

  const providerParam = searchParams.get(`filter[${providerFilterType}]`);
  const providerTypeParam = searchParams.get(
    `filter[${FilterType.PROVIDER_TYPE}]`,
  );

  const currentProviders = providerParam ? providerParam.split(",") : [];
  const currentProviderTypes = providerTypeParam
    ? (providerTypeParam.split(",") as ProviderType[])
    : [];

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

  // Derive available providers filtered by selected provider types
  const availableProviders =
    currentProviderTypes.length > 0
      ? providers.filter((key) => {
          const providerType = getProviderType(key);
          return providerType && currentProviderTypes.includes(providerType);
        })
      : providers;

  // Derive available scans filtered by selected providers and provider types
  const availableScans = enableScanRelation
    ? currentProviders.length > 0 || currentProviderTypes.length > 0
      ? completedScanIds.filter((scanId) => {
          const scanDetail = scanDetails.find(
            (detail) => Object.keys(detail)[0] === scanId,
          );
          if (!scanDetail) return false;

          const scanProviderId = scanDetail[scanId]?.providerInfo?.uid ?? null;
          const scanProviderType =
            (scanDetail[scanId]?.providerInfo?.provider as ProviderType) ??
            null;

          return (
            (currentProviders.length === 0 ||
              (scanProviderId && currentProviders.includes(scanProviderId))) &&
            (currentProviderTypes.length === 0 ||
              (scanProviderType &&
                currentProviderTypes.includes(scanProviderType)))
          );
        })
      : completedScanIds
    : completedScanIds;

  return {
    availableProviderIds: providerIds.length > 0 ? availableProviders : [],
    availableProviderUIDs: providerUIDs.length > 0 ? availableProviders : [],
    availableScans,
  };
};
