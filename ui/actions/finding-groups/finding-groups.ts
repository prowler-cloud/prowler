"use server";

import { redirect } from "next/navigation";

import { apiBaseUrl, getAuthHeaders } from "@/lib";
import { appendSanitizedProviderFilters } from "@/lib/provider-filters";
import { handleApiResponse } from "@/lib/server-actions-helper";

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

export const getFindingGroups = async ({
  page = 1,
  pageSize = 10,
  sort = "",
  filters = {},
}) => {
  const headers = await getAuthHeaders({ contentType: false });

  if (isNaN(Number(page)) || page < 1) redirect("/findings");

  const url = new URL(`${apiBaseUrl}/finding-groups`);

  if (page) url.searchParams.append("page[number]", page.toString());
  if (pageSize) url.searchParams.append("page[size]", pageSize.toString());
  if (sort) url.searchParams.append("sort", sort);

  appendSanitizedProviderFilters(url, mapSearchFilter(filters));

  try {
    const response = await fetch(url.toString(), { headers });
    return handleApiResponse(response);
  } catch (error) {
    console.error("Error fetching finding groups:", error);
    return undefined;
  }
};

export const getLatestFindingGroups = async ({
  page = 1,
  pageSize = 10,
  sort = "",
  filters = {},
}) => {
  const headers = await getAuthHeaders({ contentType: false });

  if (isNaN(Number(page)) || page < 1) redirect("/findings");

  const url = new URL(`${apiBaseUrl}/finding-groups/latest`);

  if (page) url.searchParams.append("page[number]", page.toString());
  if (pageSize) url.searchParams.append("page[size]", pageSize.toString());
  if (sort) url.searchParams.append("sort", sort);

  appendSanitizedProviderFilters(url, mapSearchFilter(filters));

  try {
    const response = await fetch(url.toString(), { headers });
    return handleApiResponse(response);
  } catch (error) {
    console.error("Error fetching latest finding groups:", error);
    return undefined;
  }
};

export const getFindingGroupResources = async ({
  checkId,
  page = 1,
  pageSize = 20,
  filters = {},
}: {
  checkId: string;
  page?: number;
  pageSize?: number;
  filters?: Record<string, string | string[] | undefined>;
}) => {
  const headers = await getAuthHeaders({ contentType: false });

  const url = new URL(
    `${apiBaseUrl}/finding-groups/${encodeURIComponent(checkId)}/resources`,
  );

  if (page) url.searchParams.append("page[number]", page.toString());
  if (pageSize) url.searchParams.append("page[size]", pageSize.toString());
  // sort=-status is kept for future-proofing: if the filter[status]=FAIL
  // constraint is ever relaxed to allow multiple statuses, the sort ensures
  // FAIL resources still appear first in the result set.
  url.searchParams.append("sort", "-status");

  appendSanitizedProviderFilters(url, filters);

  // Use .set() AFTER appendSanitizedProviderFilters so our hardcoded FAIL
  // always wins, even if the caller passed a different filter[status] value.
  // Using .set() instead of .append() prevents duplicate filter[status] params.
  url.searchParams.set("filter[status]", "FAIL");

  try {
    const response = await fetch(url.toString(), {
      headers,
    });

    return handleApiResponse(response);
  } catch (error) {
    console.error("Error fetching finding group resources:", error);
    return undefined;
  }
};

export const getLatestFindingGroupResources = async ({
  checkId,
  page = 1,
  pageSize = 20,
  filters = {},
}: {
  checkId: string;
  page?: number;
  pageSize?: number;
  filters?: Record<string, string | string[] | undefined>;
}) => {
  const headers = await getAuthHeaders({ contentType: false });

  const url = new URL(
    `${apiBaseUrl}/finding-groups/latest/${encodeURIComponent(checkId)}/resources`,
  );

  if (page) url.searchParams.append("page[number]", page.toString());
  if (pageSize) url.searchParams.append("page[size]", pageSize.toString());
  // sort=-status is kept for future-proofing: if the filter[status]=FAIL
  // constraint is ever relaxed to allow multiple statuses, the sort ensures
  // FAIL resources still appear first in the result set.
  url.searchParams.append("sort", "-status");

  appendSanitizedProviderFilters(url, filters);

  // Use .set() AFTER appendSanitizedProviderFilters so our hardcoded FAIL
  // always wins, even if the caller passed a different filter[status] value.
  // Using .set() instead of .append() prevents duplicate filter[status] params.
  url.searchParams.set("filter[status]", "FAIL");

  try {
    const response = await fetch(url.toString(), {
      headers,
    });

    return handleApiResponse(response);
  } catch (error) {
    console.error("Error fetching latest finding group resources:", error);
    return undefined;
  }
};
