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
