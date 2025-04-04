"use server";

import { revalidatePath } from "next/cache";
import { redirect } from "next/navigation";

import { apiBaseUrl, getAuthHeaders, parseStringify } from "@/lib";

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
    const data = await findings.json();
    const parsedData = parseStringify(data);
    revalidatePath("/findings");
    return parsedData;
  } catch (error) {
    // eslint-disable-next-line no-console
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

    if (!response.ok) {
      throw new Error(`Failed to fetch metadata info: ${response.statusText}`);
    }

    const parsedData = parseStringify(await response.json());

    return parsedData;
  } catch (error) {
    // eslint-disable-next-line no-console
    console.error("Error fetching metadata info:", error);
    return undefined;
  }
};
