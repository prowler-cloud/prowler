"use server";

import { redirect } from "next/navigation";

import { apiBaseUrl, getAuthHeaders } from "@/lib";
import { handleApiResponse } from "@/lib/server-actions-helper";
import { FindingsResponse } from "@/types";

interface IncludedItem {
  type: string;
  id: string;
  attributes?: { provider?: string };
  relationships?: { provider?: { data?: { id: string } } };
}

type FindingsApiResponse = FindingsResponse & {
  included?: IncludedItem[];
};

const filterMongoFindings = <T extends FindingsApiResponse | null | undefined>(
  result: T,
): T => {
  if (!result?.data) return result;

  const included = (result as FindingsApiResponse).included || [];

  // Get IDs of providers containing "mongo" in included items
  const mongoProviderIds = new Set(
    included
      .filter(
        (item) =>
          item.type === "providers" &&
          item.attributes?.provider?.toLowerCase().includes("mongo"),
      )
      .map((item) => item.id),
  );

  // Filter out findings associated with mongo providers
  result.data = result.data.filter((finding) => {
    const scanId = finding.relationships?.scan?.data?.id;
    // Find the scan in included items
    const scan = included.find(
      (item) => item.type === "scans" && item.id === scanId,
    );
    const providerId = scan?.relationships?.provider?.data?.id;
    return !providerId || !mongoProviderIds.has(providerId);
  });

  // Filter out mongo-related included items
  if ((result as FindingsApiResponse).included) {
    (result as FindingsApiResponse).included = included.filter(
      (item) =>
        !(
          item.type === "providers" &&
          item.attributes?.provider?.toLowerCase().includes("mongo")
        ),
    );
  }

  return result;
};

export const getFindings = async ({
  page = 1,
  pageSize = 10,
  query = "",
  sort = "",
  filters = {},
}) => {
  const headers = await getAuthHeaders({ contentType: false });

  if (isNaN(Number(page)) || page < 1)
    redirect("findings?include=resources,scan.provider");

  const url = new URL(`${apiBaseUrl}/findings?include=resources,scan.provider`);

  if (page) url.searchParams.append("page[number]", page.toString());
  if (pageSize) url.searchParams.append("page[size]", pageSize.toString());

  if (query) url.searchParams.append("filter[search]", query);
  if (sort) url.searchParams.append("sort", sort);

  Object.entries(filters).forEach(([key, value]) => {
    url.searchParams.append(key, String(value));
  });

  try {
    const findings = await fetch(url.toString(), {
      headers,
    });

    const result = await handleApiResponse(findings);

    return filterMongoFindings(result);
  } catch (error) {
    console.error("Error fetching findings:", error);
    return undefined;
  }
};

export const getLatestFindings = async ({
  page = 1,
  pageSize = 10,
  query = "",
  sort = "",
  filters = {},
}) => {
  const headers = await getAuthHeaders({ contentType: false });

  if (isNaN(Number(page)) || page < 1)
    redirect("findings?include=resources,scan.provider");

  const url = new URL(
    `${apiBaseUrl}/findings/latest?include=resources,scan.provider`,
  );

  if (page) url.searchParams.append("page[number]", page.toString());
  if (pageSize) url.searchParams.append("page[size]", pageSize.toString());

  if (query) url.searchParams.append("filter[search]", query);
  if (sort) url.searchParams.append("sort", sort);

  Object.entries(filters).forEach(([key, value]) => {
    url.searchParams.append(key, String(value));
  });

  try {
    const findings = await fetch(url.toString(), {
      headers,
    });

    const result = await handleApiResponse(findings);

    return filterMongoFindings(result);
  } catch (error) {
    console.error("Error fetching findings:", error);
    return undefined;
  }
};

export const getMetadataInfo = async ({
  query = "",
  sort = "",
  filters = {},
}) => {
  const headers = await getAuthHeaders({ contentType: false });

  const url = new URL(`${apiBaseUrl}/findings/metadata`);

  if (query) url.searchParams.append("filter[search]", query);
  if (sort) url.searchParams.append("sort", sort);

  Object.entries(filters).forEach(([key, value]) => {
    // Define filters to exclude
    const excludedFilters = ["region__in", "service__in", "resource_type__in"];
    if (
      key !== "filter[search]" &&
      !excludedFilters.some((filter) => key.includes(filter))
    ) {
      url.searchParams.append(key, String(value));
    }
  });

  try {
    const response = await fetch(url.toString(), {
      headers,
    });

    return handleApiResponse(response);
  } catch (error) {
    console.error("Error fetching metadata info:", error);
    return undefined;
  }
};

export const getLatestMetadataInfo = async ({
  query = "",
  sort = "",
  filters = {},
}) => {
  const headers = await getAuthHeaders({ contentType: false });

  const url = new URL(`${apiBaseUrl}/findings/metadata/latest`);

  if (query) url.searchParams.append("filter[search]", query);
  if (sort) url.searchParams.append("sort", sort);

  Object.entries(filters).forEach(([key, value]) => {
    // Define filters to exclude
    const excludedFilters = ["region__in", "service__in", "resource_type__in"];
    if (
      key !== "filter[search]" &&
      !excludedFilters.some((filter) => key.includes(filter))
    ) {
      url.searchParams.append(key, String(value));
    }
  });

  try {
    const response = await fetch(url.toString(), {
      headers,
    });

    return handleApiResponse(response);
  } catch (error) {
    console.error("Error fetching metadata info:", error);
    return undefined;
  }
};

export const getFindingById = async (findingId: string, include = "") => {
  const headers = await getAuthHeaders({ contentType: false });

  const url = new URL(`${apiBaseUrl}/findings/${findingId}`);
  if (include) url.searchParams.append("include", include);

  try {
    const response = await fetch(url.toString(), {
      headers,
    });

    return handleApiResponse(response);
  } catch (error) {
    console.error("Error fetching finding by ID:", error);
    return undefined;
  }
};
