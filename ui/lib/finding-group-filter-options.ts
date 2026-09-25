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

interface FindingGroupFilterFetcherParams {
  page: number;
  pageSize: number;
  sort: string;
  filters: Record<string, string | string[] | undefined>;
}

export type FindingGroupFilterFetcher = (
  params: FindingGroupFilterFetcherParams,
) => Promise<unknown>;

export function excludeFindingGroupOwnFilters(
  filters: Record<string, string | string[] | undefined>,
) {
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

/** Titles for already-selected checks; one small request, none without a selection. */
export async function getSelectedFindingCheckOptions({
  fetchFindingGroups,
  filters,
  selectedCheckIds,
}: {
  fetchFindingGroups: FindingGroupFilterFetcher;
  filters: Record<string, string | string[] | undefined>;
  selectedCheckIds: string[];
}) {
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

  return adaptFindingGroupsResponse(response).map((group) => ({
    checkId: group.checkId,
    checkTitle: group.checkTitle,
  }));
}

export async function getFindingGroupFilterOptions({
  fetchFindingGroups,
  filters,
}: {
  fetchFindingGroups: FindingGroupFilterFetcher;
  filters: Record<string, string | string[] | undefined>;
}) {
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
  const fetchNextPage = async () => {
    while (pendingPages.length > 0) {
      const page = pendingPages.shift() as number;
      remainingPages[page - 2] = await fetchPage(page);
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
      fetchNextPage,
    ),
  );

  const options = new Map<string, { checkId: string; checkTitle: string }>();
  for (const response of [firstPage, ...remainingPages]) {
    for (const group of adaptFindingGroupsResponse(response)) {
      options.set(group.checkId, {
        checkId: group.checkId,
        checkTitle: group.checkTitle,
      });
    }
  }

  return Array.from(options.values());
}
