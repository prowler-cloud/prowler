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

/**
 * Replaces a specific field name inside a filter-style key of an object.
 * @param obj - The input object with filter-style keys (e.g., { 'filter[inserted_at]': '2025-05-21' }).
 * @param oldField - The field name to be replaced (e.g., 'inserted_at').
 * @param newField - The field name to replace with (e.g., 'updated_at').
 * @returns A new object with the updated filter key if a match is found.
 */
export function replaceFilterFieldKey(
  obj: Record<string, string>,
  oldField: string,
  newField: string,
): Record<string, string> {
  const fieldObj: Record<string, string> = {};

  for (const key in obj) {
    const match = key.match(/^filter\[(.+)\]$/);
    if (match && match[1] === oldField) {
      const newKey = `filter[${newField}]`;
      fieldObj[newKey] = obj[key];
    } else {
      fieldObj[key] = obj[key];
    }
  }

  return fieldObj;
}
