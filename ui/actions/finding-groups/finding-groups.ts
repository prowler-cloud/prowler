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

function normalizeFindingGroupResourceFilters(
  filters: Record<string, string | string[] | undefined>,
): Record<string, string | string[] | undefined> {
  const normalized = { ...filters };
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
  const normalizedFilters = normalizeFindingGroupResourceFilters(filters);

  const url = new URL(
    `${apiBaseUrl}/finding-groups/${encodeURIComponent(checkId)}/resources`,
  );

  if (page) url.searchParams.append("page[number]", page.toString());
  if (pageSize) url.searchParams.append("page[size]", pageSize.toString());
  // Keep FAIL-first ordering when multiple statuses are returned.
  url.searchParams.append("sort", "-status");

  appendSanitizedProviderFilters(url, normalizedFilters);

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
  const normalizedFilters = normalizeFindingGroupResourceFilters(filters);

  const url = new URL(
    `${apiBaseUrl}/finding-groups/latest/${encodeURIComponent(checkId)}/resources`,
  );

  if (page) url.searchParams.append("page[number]", page.toString());
  if (pageSize) url.searchParams.append("page[size]", pageSize.toString());
  // Keep FAIL-first ordering when multiple statuses are returned.
  url.searchParams.append("sort", "-status");

  appendSanitizedProviderFilters(url, normalizedFilters);

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
