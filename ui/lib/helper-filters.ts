import { ProviderProps, ProvidersApiResponse, ScanProps } from "@/types";
import { ScanEntity } from "@/types/scans";

/**
 * Extracts normalized filters and search query from the URL search params.
 * Used Server Side Rendering (SSR). There is a hook (useUrlFilters) for client side.
 */
export const extractFiltersAndQuery = (
  searchParams: Record<string, unknown>,
) => {
  const filters: Record<string, string> = {
    ...Object.fromEntries(
      Object.entries(searchParams)
        .filter(([key]) => key.startsWith("filter["))
        .map(([key, value]) => [
          key,
          Array.isArray(value) ? value.join(",") : value?.toString() || "",
        ]),
    ),
  };

  const query = filters["filter[search]"] || "";
  return { filters, query };
};

/**
 * Returns true if there are any scan or inserted_at filters in the search params.
 * Used to determine whether to call the full findings endpoint.
 */
export const hasDateOrScanFilter = (searchParams: Record<string, unknown>) =>
  Object.keys(searchParams).some(
    (key) => key.includes("inserted_at") || key.includes("scan__in"),
  );

/**
 * Encodes sort strings by removing leading "+" symbols.
 */
export const encodeSort = (sort?: string) => sort?.replace(/^\+/, "") || "";

/**
 * Extracts the sort string and the stable key to use in Suspense boundaries.
 */
export const extractSortAndKey = (searchParams: Record<string, unknown>) => {
  const searchParamsKey = JSON.stringify(searchParams || {});
  const rawSort = searchParams.sort?.toString();
  const encodedSort = encodeSort(rawSort);

  return { searchParamsKey, rawSort, encodedSort };
};

export const isScanEntity = (entity: ScanEntity) => {
  return entity && entity.providerInfo && entity.attributes;
};

/**
 * Creates a scan details mapping for filters from completed scans.
 * Used to provide detailed information for scan filters in the UI.
 */
export const createScanDetailsMapping = (
  completedScans: ScanProps[],
  providersData?: ProvidersApiResponse,
) => {
  if (!completedScans || completedScans.length === 0) {
    return [];
  }

  const scanMappings = completedScans.map((scan: ScanProps) => {
    // Get provider info from providerInfo if available, or find from providers data
    let providerInfo = scan.providerInfo;

    if (!providerInfo && scan.relationships?.provider?.data?.id) {
      const provider = providersData?.data?.find(
        (p: ProviderProps) => p.id === scan.relationships.provider.data.id,
      );
      if (provider) {
        providerInfo = {
          provider: provider.attributes.provider,
          alias: provider.attributes.alias,
          uid: provider.attributes.uid,
        };
      }
    }

    return {
      [scan.id]: {
        id: scan.id,
        providerInfo: {
          provider: providerInfo?.provider || "aws",
          alias: providerInfo?.alias,
          uid: providerInfo?.uid,
        },
        attributes: {
          name: scan.attributes.name,
          completed_at: scan.attributes.completed_at,
        },
      },
    };
  });

  return scanMappings;
};
