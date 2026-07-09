/** Params the findings DataTable pushes to the URL. They must not remount the
 *  detail view: the client accordion would collapse and lose its state, while
 *  the findings hook already refetches from useSearchParams on its own. */
const TABLE_STATE_PARAMS = ["page", "pageSize", "sort"];

/**
 * Suspense key for the compliance detail views, stable across table-state
 * navigations (pagination/sort) so only real query changes remount the tree.
 */
export const buildSearchParamsKey = (
  searchParams: Record<string, string | undefined>,
): string =>
  JSON.stringify(
    Object.fromEntries(
      Object.entries(searchParams).filter(
        ([key]) => !TABLE_STATE_PARAMS.includes(key),
      ),
    ),
  );
