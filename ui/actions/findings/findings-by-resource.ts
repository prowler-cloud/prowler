"use server";

import {
  getFindingGroupResources,
  getLatestFindingGroupResources,
} from "@/actions/finding-groups";
import { apiBaseUrl, getAuthHeaders } from "@/lib";
import { runWithConcurrencyLimit } from "@/lib/concurrency";
import { appendSanitizedProviderTypeFilters } from "@/lib/provider-filters";
import { handleApiResponse } from "@/lib/server-actions-helper";

const FINDING_IDS_RESOLUTION_PAGE_SIZE = 500;
const FINDING_IDS_RESOLUTION_CONCURRENCY = 4;
const FINDING_GROUP_RESOURCES_RESOLUTION_PAGE_SIZE = 500;
const FINDING_FIELDS = "uid";

interface ResolveFindingIdsByCheckIdsParams {
  checkIds: string[];
  filters?: Record<string, string>;
  hasDateOrScanFilter?: boolean;
}

interface ResolveFindingIdsByVisibleGroupResourcesParams {
  checkId: string;
  filters?: Record<string, string>;
  hasDateOrScanFilter?: boolean;
  resourceSearch?: string;
}

interface FindingIdsPageResponse {
  ids: string[];
  totalPages: number;
}

interface FindingGroupResourceFindingIdsPageResponse {
  findingIds: string[];
  totalPages: number;
}

function createFindingsResolutionUrl({
  checkIds,
  filters = {},
  page,
  hasDateOrScanFilter = false,
}: ResolveFindingIdsByCheckIdsParams & {
  page: number;
}): URL {
  const endpoint = hasDateOrScanFilter ? "findings" : "findings/latest";
  const url = new URL(`${apiBaseUrl}/${endpoint}`);

  url.searchParams.append("filter[check_id__in]", checkIds.join(","));
  url.searchParams.append("filter[muted]", "false");
  url.searchParams.append("fields[findings]", FINDING_FIELDS);
  url.searchParams.append("page[number]", page.toString());
  url.searchParams.append(
    "page[size]",
    FINDING_IDS_RESOLUTION_PAGE_SIZE.toString(),
  );

  appendSanitizedProviderTypeFilters(url, filters);

  return url;
}

async function fetchFindingIdsPage({
  headers,
  page,
  ...params
}: ResolveFindingIdsByCheckIdsParams & {
  headers: HeadersInit;
  page: number;
}): Promise<FindingIdsPageResponse> {
  const response = await fetch(
    createFindingsResolutionUrl({ ...params, page }).toString(),
    {
      headers,
    },
  );
  const data = await handleApiResponse(response);

  if (!data?.data || !Array.isArray(data.data)) {
    return { ids: [], totalPages: 1 };
  }

  return {
    ids: data.data
      .map((item: { id?: string }) => item.id)
      .filter((id: string | undefined): id is string => Boolean(id)),
    totalPages: data?.meta?.pagination?.pages ?? 1,
  };
}

async function fetchFindingGroupResourceFindingIdsPage({
  checkId,
  filters = {},
  hasDateOrScanFilter = false,
  page,
  resourceSearch,
}: ResolveFindingIdsByVisibleGroupResourcesParams & {
  page: number;
}): Promise<FindingGroupResourceFindingIdsPageResponse> {
  const fetchFn = hasDateOrScanFilter
    ? getFindingGroupResources
    : getLatestFindingGroupResources;

  const resolvedFilters: Record<string, string> = {
    ...filters,
    "filter[status]": "FAIL",
    "filter[muted]": "false",
  };
  if (resourceSearch) {
    resolvedFilters["filter[name__icontains]"] = resourceSearch;
  }

  const response = await fetchFn({
    checkId,
    page,
    pageSize: FINDING_GROUP_RESOURCES_RESOLUTION_PAGE_SIZE,
    filters: resolvedFilters,
  });

  const data = response?.data;

  if (!data || !Array.isArray(data)) {
    return { findingIds: [], totalPages: 1 };
  }

  return {
    findingIds: data
      .map(
        (item: { attributes?: { finding_id?: string } }) =>
          item.attributes?.finding_id,
      )
      .filter((id: string | undefined): id is string => Boolean(id)),
    totalPages: response?.meta?.pagination?.pages ?? 1,
  };
}

/**
 * Resolves check IDs into actual finding UUIDs.
 * Used at the group level where each row represents a check_id.
 */
export const resolveFindingIdsByCheckIds = async ({
  checkIds,
  filters = {},
  hasDateOrScanFilter = false,
}: ResolveFindingIdsByCheckIdsParams): Promise<string[]> => {
  if (checkIds.length === 0) {
    return [];
  }

  const headers = await getAuthHeaders({ contentType: false });

  try {
    const firstPage = await fetchFindingIdsPage({
      checkIds,
      filters,
      hasDateOrScanFilter,
      headers,
      page: 1,
    });

    const remainingPages = Array.from(
      { length: Math.max(0, firstPage.totalPages - 1) },
      (_, index) => index + 2,
    );

    const remainingResults = await runWithConcurrencyLimit(
      remainingPages,
      FINDING_IDS_RESOLUTION_CONCURRENCY,
      async (page) =>
        fetchFindingIdsPage({
          checkIds,
          filters,
          hasDateOrScanFilter,
          headers,
          page,
        }),
    );

    return Array.from(
      new Set([
        ...firstPage.ids,
        ...remainingResults.flatMap((result) => result.ids),
      ]),
    );
  } catch (error) {
    console.error("Error resolving finding IDs by check IDs:", error);
    return [];
  }
};

/**
 * Resolves a finding-group row to the actual finding UUIDs for the resources
 * currently visible in that group.
 *
 * Extracts finding_id directly from the group resources endpoint response,
 * filtering server-side by status=FAIL and muted=false. No second resolution
 * round-trip to /findings/latest is needed.
 */
export const resolveFindingIdsByVisibleGroupResources = async ({
  checkId,
  filters = {},
  hasDateOrScanFilter = false,
  resourceSearch,
}: ResolveFindingIdsByVisibleGroupResourcesParams): Promise<string[]> => {
  try {
    const firstPage = await fetchFindingGroupResourceFindingIdsPage({
      checkId,
      filters,
      hasDateOrScanFilter,
      page: 1,
      resourceSearch,
    });

    const remainingPages = Array.from(
      { length: Math.max(0, firstPage.totalPages - 1) },
      (_, index) => index + 2,
    );

    const remainingResults = await runWithConcurrencyLimit(
      remainingPages,
      FINDING_IDS_RESOLUTION_CONCURRENCY,
      (page) =>
        fetchFindingGroupResourceFindingIdsPage({
          checkId,
          filters,
          hasDateOrScanFilter,
          page,
          resourceSearch,
        }),
    );

    return Array.from(
      new Set([
        ...firstPage.findingIds,
        ...remainingResults.flatMap((result) => result.findingIds),
      ]),
    );
  } catch (error) {
    console.error(
      "Error resolving finding IDs from visible group resources:",
      error,
    );
    return [];
  }
};

export const getLatestFindingsByResourceUid = async ({
  resourceUid,
  page = 1,
  pageSize = 50,
  includeMuted = false,
}: {
  resourceUid: string;
  page?: number;
  pageSize?: number;
  includeMuted?: boolean;
}) => {
  const headers = await getAuthHeaders({ contentType: false });

  const url = new URL(
    `${apiBaseUrl}/findings/latest?include=resources,scan.provider`,
  );

  url.searchParams.append("filter[resource_uid]", resourceUid);
  url.searchParams.append("filter[muted]", includeMuted ? "include" : "false");
  url.searchParams.append("sort", "-severity,-updated_at");
  if (page) url.searchParams.append("page[number]", page.toString());
  if (pageSize) url.searchParams.append("page[size]", pageSize.toString());

  try {
    const findings = await fetch(url.toString(), {
      headers,
    });

    return handleApiResponse(findings);
  } catch (error) {
    console.error("Error fetching findings by resource UID:", error);
    return undefined;
  }
};
