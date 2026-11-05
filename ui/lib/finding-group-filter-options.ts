import { adaptFindingGroupsResponse } from "@/actions/finding-groups/finding-groups.adapter";

const FINDING_GROUP_FILTER_OPTION_PAGE_SIZE = 100;
// Options only need a stable page order; the table's composite sort costs an
// extra aggregation per page on the API.
const FINDING_GROUP_FILTER_OPTION_SORT = "check_id";
// Each page can hit the raw findings aggregation, so bound the DB fan-out.
const FINDING_GROUP_FILTER_OPTION_CONCURRENCY = 4;
const FINDING_GROUP_OWN_FILTER_KEYS = new Set([
  "filter[check_id]",
  "filter[check_id__in]",
]);

type FindingGroupFilters = Record<string, string | string[] | undefined>;

interface FindingGroupFilterFetcherParams {
  page: number;
  pageSize: number;
  sort: string;
  filters: FindingGroupFilters;
}

export type FindingGroupFilterFetcher = (
  params: FindingGroupFilterFetcherParams,
) => Promise<unknown>;

export interface FindingGroupCheckOption {
  checkId: string;
  checkTitle: string;
}

export function excludeFindingGroupOwnFilters(filters: FindingGroupFilters) {
  return Object.fromEntries(
    Object.entries(filters).filter(
      ([key]) => !FINDING_GROUP_OWN_FILTER_KEYS.has(key),
    ),
  );
}

function getTotalPages(response: unknown, currentPage: number): number {
  if (!response || typeof response !== "object" || !("meta" in response)) {
    return currentPage;
  }

  const meta = response.meta;
  if (!meta || typeof meta !== "object" || !("pagination" in meta)) {
    return currentPage;
  }

  const pagination = meta.pagination;
  if (
    !pagination ||
    typeof pagination !== "object" ||
    !("pages" in pagination)
  ) {
    return currentPage;
  }

  return typeof pagination.pages === "number" ? pagination.pages : currentPage;
}

function toCheckOptions(response: unknown): FindingGroupCheckOption[] {
  return adaptFindingGroupsResponse(response).map((group) => ({
    checkId: group.checkId,
    checkTitle: group.checkTitle,
  }));
}

/** Titles for the checks already selected in the URL: one request, none without a selection. */
export async function getSelectedFindingCheckOptions({
  fetchFindingGroups,
  filters,
  selectedCheckIds,
}: {
  fetchFindingGroups: FindingGroupFilterFetcher;
  filters: FindingGroupFilters;
  selectedCheckIds: string[];
}): Promise<FindingGroupCheckOption[]> {
  const uniqueIds = Array.from(new Set(selectedCheckIds.filter(Boolean)));
  if (uniqueIds.length === 0) return [];

  const response = await fetchFindingGroups({
    filters: {
      ...excludeFindingGroupOwnFilters(filters),
      "filter[check_id__in]": uniqueIds.join(","),
    },
    page: 1,
    pageSize: FINDING_GROUP_FILTER_OPTION_PAGE_SIZE,
    sort: FINDING_GROUP_FILTER_OPTION_SORT,
  });

  return toCheckOptions(response);
}

/** Every check for the given filters, walking the pages a few at a time. */
export async function getFindingGroupFilterOptions({
  fetchFindingGroups,
  filters,
}: {
  fetchFindingGroups: FindingGroupFilterFetcher;
  filters: FindingGroupFilters;
}): Promise<FindingGroupCheckOption[]> {
  const optionFilters = excludeFindingGroupOwnFilters(filters);
  const fetchPage = (page: number) =>
    fetchFindingGroups({
      filters: optionFilters,
      page,
      pageSize: FINDING_GROUP_FILTER_OPTION_PAGE_SIZE,
      sort: FINDING_GROUP_FILTER_OPTION_SORT,
    });

  const firstPage = await fetchPage(1);
  const totalPages = getTotalPages(firstPage, 1);
  const pendingPages = Array.from(
    { length: Math.max(totalPages - 1, 0) },
    (_, index) => index + 2,
  );
  const remainingPages: unknown[] = [];
  // One rejection fails the whole walk, so the other workers stop dequeuing.
  let failed = false;
  const drainPendingPages = async () => {
    while (!failed && pendingPages.length > 0) {
      const page = pendingPages.shift() as number;
      try {
        remainingPages[page - 2] = await fetchPage(page);
      } catch (error) {
        failed = true;
        throw error;
      }
    }
  };
  await Promise.all(
    Array.from(
      {
        length: Math.min(
          FINDING_GROUP_FILTER_OPTION_CONCURRENCY,
          pendingPages.length,
        ),
      },
      drainPendingPages,
    ),
  );

  const options = new Map<string, FindingGroupCheckOption>();
  for (const response of [firstPage, ...remainingPages]) {
    for (const option of toCheckOptions(response)) {
      options.set(option.checkId, option);
    }
  }

  return Array.from(options.values());
}
