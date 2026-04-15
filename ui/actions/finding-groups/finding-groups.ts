"use server";

import { redirect } from "next/navigation";

import { apiBaseUrl, getAuthHeaders } from "@/lib";
import { appendSanitizedProviderFilters } from "@/lib/provider-filters";
import { handleApiResponse } from "@/lib/server-actions-helper";
import { FilterParam } from "@/types/filters";

/**
 * Maps filter[search] to filter[check_title__icontains] for finding-groups.
 * The finding-groups endpoint supports check_title__icontains for substring
 * matching on the human-readable check title displayed in the table.
 */
function mapSearchFilter(
  filters: Record<string, string | string[] | undefined>,
): Record<string, string | string[] | undefined> {
  const mapped = { ...filters };
  const searchValue = mapped["filter[search]"];
  if (searchValue) {
    mapped["filter[check_title__icontains]"] = searchValue;
    delete mapped["filter[search]"];
  }
  return mapped;
}

function splitCsvFilterValues(value: string | string[] | undefined): string[] {
  if (Array.isArray(value)) {
    return value
      .flatMap((item) => item.split(","))
      .map((item) => item.trim())
      .filter(Boolean);
  }

  if (typeof value === "string") {
    return value
      .split(",")
      .map((item) => item.trim())
      .filter(Boolean);
  }

  return [];
}

/**
 * Filters that belong to finding-groups but are NOT valid for the
 * finding-group resources sub-endpoint. These must be stripped before
 * calling the resources API to avoid empty results.
 */
const FINDING_GROUP_RESOURCE_UNSUPPORTED_FILTERS: FilterParam[] = [
  "filter[service__in]",
  "filter[scan__in]",
  "filter[scan_id]",
  "filter[scan_id__in]",
];

function normalizeFindingGroupResourceFilters(
  filters: Record<string, string | string[] | undefined>,
): Record<string, string | string[] | undefined> {
  const normalized = Object.fromEntries(
    Object.entries(filters).filter(
      ([key]) =>
        !FINDING_GROUP_RESOURCE_UNSUPPORTED_FILTERS.includes(
          key as FilterParam,
        ),
    ),
  );

  const exactStatusFilter = normalized["filter[status]"];

  if (exactStatusFilter !== undefined) {
    delete normalized["filter[status__in]"];
    return normalized;
  }

  const statusValues = splitCsvFilterValues(normalized["filter[status__in]"]);
  if (statusValues.length === 1) {
    normalized["filter[status]"] = statusValues[0];
    delete normalized["filter[status__in]"];
  }

  return normalized;
}

const DEFAULT_FINDING_GROUPS_SORT =
  "-status,-new_fail_count,-changed_fail_count,-severity,-fail_count,-last_seen_at";

const DEFAULT_FINDING_GROUPS_SORT_WITH_MUTED =
  "-status,-new_fail_count,-changed_fail_count,-severity,-new_fail_muted_count,-changed_fail_muted_count,-fail_count,-fail_muted_count,-last_seen_at";

const DEFAULT_FINDING_GROUP_RESOURCES_SORT =
  "-status,-delta,-severity,-last_seen_at";

interface FetchFindingGroupsParams {
  page?: number;
  pageSize?: number;
  sort?: string;
  filters?: Record<string, string | string[] | undefined>;
}

function includesMutedFindings(
  filters: Record<string, string | string[] | undefined>,
): boolean {
  const mutedFilter = filters["filter[muted]"];

  if (Array.isArray(mutedFilter)) {
    return mutedFilter.includes("include");
  }

  return mutedFilter === "include";
}

function getDefaultFindingGroupsSort(
  filters: Record<string, string | string[] | undefined>,
): string {
  return includesMutedFindings(filters)
    ? DEFAULT_FINDING_GROUPS_SORT_WITH_MUTED
    : DEFAULT_FINDING_GROUPS_SORT;
}

async function fetchFindingGroupsEndpoint(
  endpoint: string,
  { page = 1, pageSize = 10, sort, filters = {} }: FetchFindingGroupsParams,
) {
  const headers = await getAuthHeaders({ contentType: false });
  const resolvedSort = sort ?? getDefaultFindingGroupsSort(filters);

  if (isNaN(Number(page)) || page < 1) redirect("/findings");

  const url = new URL(`${apiBaseUrl}/${endpoint}`);

  if (page) url.searchParams.append("page[number]", page.toString());
  if (pageSize) url.searchParams.append("page[size]", pageSize.toString());
  if (resolvedSort) url.searchParams.append("sort", resolvedSort);

  appendSanitizedProviderFilters(url, mapSearchFilter(filters));

  try {
    const response = await fetch(url.toString(), { headers });
    return handleApiResponse(response);
  } catch (error) {
    console.error(`Error fetching ${endpoint}:`, error);
    return undefined;
  }
}

export const getFindingGroups = async (params: FetchFindingGroupsParams = {}) =>
  fetchFindingGroupsEndpoint("finding-groups", params);

export const getLatestFindingGroups = async (
  params: FetchFindingGroupsParams = {},
) => fetchFindingGroupsEndpoint("finding-groups/latest", params);

interface FetchFindingGroupResourcesParams {
  checkId: string;
  page?: number;
  pageSize?: number;
  filters?: Record<string, string | string[] | undefined>;
}

async function fetchFindingGroupResourcesEndpoint(
  endpointPrefix: string,
  {
    checkId,
    page = 1,
    pageSize = 20,
    filters = {},
  }: FetchFindingGroupResourcesParams,
) {
  const headers = await getAuthHeaders({ contentType: false });
  const normalizedFilters = normalizeFindingGroupResourceFilters(filters);

  const url = new URL(
    `${apiBaseUrl}/${endpointPrefix}/${encodeURIComponent(checkId)}/resources`,
  );

  if (page) url.searchParams.append("page[number]", page.toString());
  if (pageSize) url.searchParams.append("page[size]", pageSize.toString());
  url.searchParams.append("sort", DEFAULT_FINDING_GROUP_RESOURCES_SORT);

  appendSanitizedProviderFilters(url, normalizedFilters);

  try {
    const response = await fetch(url.toString(), { headers });
    return handleApiResponse(response);
  } catch (error) {
    console.error(`Error fetching ${endpointPrefix} resources:`, error);
    return undefined;
  }
}

export const getFindingGroupResources = async (
  params: FetchFindingGroupResourcesParams,
) => fetchFindingGroupResourcesEndpoint("finding-groups", params);

export const getLatestFindingGroupResources = async (
  params: FetchFindingGroupResourcesParams,
) => fetchFindingGroupResourcesEndpoint("finding-groups/latest", params);
