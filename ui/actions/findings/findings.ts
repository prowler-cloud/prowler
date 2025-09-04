"use server";

import { redirect } from "next/navigation";

import { apiBaseUrl, getAuthHeaders, handleApiResponse } from "@/lib";

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
    return handleApiResponse(findings, "/findings");
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
    return handleApiResponse(findings, "/findings");
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
