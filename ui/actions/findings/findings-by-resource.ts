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

interface ResolveFindingIdsParams {
  checkId: string;
  resourceUids: string[];
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

interface FindingGroupResourceUidsPageResponse {
  resourceUids: string[];
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

function chunkValues<T>(values: T[], chunkSize: number): T[][] {
  const chunks: T[][] = [];
  for (let index = 0; index < values.length; index += chunkSize) {
    chunks.push(values.slice(index, index + chunkSize));
  }
  return chunks;
}

function createResourceFindingResolutionUrl({
  checkId,
  resourceUids,
  filters = {},
  hasDateOrScanFilter = false,
}: ResolveFindingIdsParams): URL {
  const endpoint = hasDateOrScanFilter ? "findings" : "findings/latest";
  const url = new URL(`${apiBaseUrl}/${endpoint}`);

  url.searchParams.append("filter[check_id]", checkId);
  url.searchParams.append("filter[resource_uid__in]", resourceUids.join(","));
  url.searchParams.append("filter[muted]", "false");
  url.searchParams.append("page[size]", resourceUids.length.toString());

  appendSanitizedProviderTypeFilters(url, filters);

  return url;
}

async function fetchFindingIdsForResourceUids({
  headers,
  ...params
}: ResolveFindingIdsParams & {
  headers: HeadersInit;
}): Promise<string[]> {
  const response = await fetch(
    createResourceFindingResolutionUrl(params).toString(),
    {
      headers,
    },
  );
  const data = await handleApiResponse(response);

  if (!data?.data || !Array.isArray(data.data)) {
    return [];
  }

  return data.data
    .map((item: { id?: string }) => item.id)
    .filter((id: string | undefined): id is string => Boolean(id));
}

function buildFindingGroupResourceFilters({
  filters = {},
  resourceSearch,
}: Pick<
  ResolveFindingIdsByVisibleGroupResourcesParams,
  "filters" | "resourceSearch"
>): Record<string, string> {
  const nextFilters = { ...filters };
  if (resourceSearch) {
    nextFilters["filter[name__icontains]"] = resourceSearch;
  }
  return nextFilters;
}

async function fetchFindingGroupResourceUidsPage({
  checkId,
  filters = {},
  hasDateOrScanFilter = false,
  page,
  resourceSearch,
}: ResolveFindingIdsByVisibleGroupResourcesParams & {
  page: number;
}): Promise<FindingGroupResourceUidsPageResponse> {
  const fetchFn = hasDateOrScanFilter
    ? getFindingGroupResources
    : getLatestFindingGroupResources;

  const response = await fetchFn({
    checkId,
    page,
    pageSize: FINDING_GROUP_RESOURCES_RESOLUTION_PAGE_SIZE,
    filters: buildFindingGroupResourceFilters({ filters, resourceSearch }),
  });

  const data = response?.data;

  if (!data || !Array.isArray(data)) {
    return { resourceUids: [], totalPages: 1 };
  }

  return {
    resourceUids: data
      .map((item: { attributes?: { resource?: { uid?: string } } }) =>
        item.attributes?.resource?.uid,
      )
      .filter((uid: string | undefined): uid is string => Boolean(uid)),
    totalPages: response?.meta?.pagination?.pages ?? 1,
  };
}

/**
 * Resolves resource UIDs + check ID into actual finding UUIDs.
 * Uses /findings/latest (or /findings when date/scan filters are active)
 * with check_id and resource_uid__in filters to batch-resolve actual finding IDs.
 */
export const resolveFindingIds = async ({
  checkId,
  resourceUids,
  filters = {},
  hasDateOrScanFilter = false,
}: ResolveFindingIdsParams): Promise<string[]> => {
  if (resourceUids.length === 0) {
    return [];
  }

  const headers = await getAuthHeaders({ contentType: false });
  const resourceUidChunks = chunkValues(
    Array.from(new Set(resourceUids)),
    FINDING_IDS_RESOLUTION_PAGE_SIZE,
  );

  try {
    const results = await runWithConcurrencyLimit(
      resourceUidChunks,
      FINDING_IDS_RESOLUTION_CONCURRENCY,
      (resourceUidChunk) =>
        fetchFindingIdsForResourceUids({
          checkId,
          resourceUids: resourceUidChunk,
          filters,
          hasDateOrScanFilter,
          headers,
        }),
    );

    return Array.from(new Set(results.flat()));
  } catch (error) {
    console.error("Error resolving finding IDs:", error);
    return [];
  }
};

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
 * Resolves a finding-group row to the actual findings for the resources
 * currently visible in that group.
 */
export const resolveFindingIdsByVisibleGroupResources = async ({
  checkId,
  filters = {},
  hasDateOrScanFilter = false,
  resourceSearch,
}: ResolveFindingIdsByVisibleGroupResourcesParams): Promise<string[]> => {
  try {
    const firstPage = await fetchFindingGroupResourceUidsPage({
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
        fetchFindingGroupResourceUidsPage({
          checkId,
          filters,
          hasDateOrScanFilter,
          page,
          resourceSearch,
        }),
    );

    const resourceUids = Array.from(
      new Set([
        ...firstPage.resourceUids,
        ...remainingResults.flatMap((result) => result.resourceUids),
      ]),
    );

    return resolveFindingIds({
      checkId,
      resourceUids,
      filters,
      hasDateOrScanFilter,
    });
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
}: {
  resourceUid: string;
  page?: number;
  pageSize?: number;
}) => {
  const headers = await getAuthHeaders({ contentType: false });

  const url = new URL(
    `${apiBaseUrl}/findings/latest?include=resources,scan.provider`,
  );

  url.searchParams.append("filter[resource_uid]", resourceUid);
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
