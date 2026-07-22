import { adaptFindingGroupsResponse } from "@/actions/finding-groups/finding-groups.adapter";

const FINDING_GROUP_FILTER_OPTION_PAGE_SIZE = 100;
const FINDING_GROUP_OWN_FILTER_KEYS = new Set([
  "filter[check_id]",
  "filter[check_id__in]",
]);

interface FindingGroupFilterFetcherParams {
  page: number;
  pageSize: number;
  filters: Record<string, string | string[] | undefined>;
}

type FindingGroupFilterFetcher = (
  params: FindingGroupFilterFetcherParams,
) => Promise<unknown>;

function excludeFindingGroupOwnFilters(
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

export async function getFindingGroupFilterOptions({
  fetchFindingGroups,
  filters,
}: {
  fetchFindingGroups: FindingGroupFilterFetcher;
  filters: Record<string, string | string[] | undefined>;
}) {
  const optionFilters = excludeFindingGroupOwnFilters(filters);
  const options = new Map<string, { checkId: string; checkTitle: string }>();
  let page = 1;

  while (true) {
    const response = await fetchFindingGroups({
      filters: optionFilters,
      page,
      pageSize: FINDING_GROUP_FILTER_OPTION_PAGE_SIZE,
    });

    for (const group of adaptFindingGroupsResponse(response)) {
      options.set(group.checkId, {
        checkId: group.checkId,
        checkTitle: group.checkTitle,
      });
    }

    if (page >= getTotalPages(response, page)) break;
    page += 1;
  }

  return Array.from(options.values());
}
