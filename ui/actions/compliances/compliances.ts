"use server";

import { apiBaseUrl, getAuthHeaders } from "@/lib";
import { handleApiResponse } from "@/lib/server-actions-helper";

export const getCompliancesOverview = async ({
  scanId,
  region,
  query,
  filters = {},
}: {
  scanId?: string;
  region?: string | string[];
  query?: string;
  filters?: Record<string, string | string[] | undefined>;
} = {}) => {
  const headers = await getAuthHeaders({ contentType: false });

  const url = new URL(`${apiBaseUrl}/compliance-overviews`);

  const setParam = (key: string, value?: string | string[]) => {
    if (!value) return;

    const serializedValue = Array.isArray(value) ? value.join(",") : value;
    if (serializedValue.trim().length > 0) {
      url.searchParams.set(key, serializedValue);
    }
  };

  Object.entries(filters).forEach(([key, value]) => setParam(key, value));

  setParam("filter[scan_id]", scanId);
  setParam("filter[region__in]", region);
  if (query) url.searchParams.set("filter[search]", query);

  try {
    const response = await fetch(url.toString(), {
      headers,
    });

    return handleApiResponse(response);
  } catch (error) {
    console.error("Error fetching compliances overview:", error);
    return undefined;
  }
};

export const getComplianceOverviewMetadataInfo = async ({
  query = "",
  sort = "",
  filters = {},
}) => {
  const headers = await getAuthHeaders({ contentType: false });

  const url = new URL(`${apiBaseUrl}/compliance-overviews/metadata`);

  if (query) url.searchParams.append("filter[search]", query);
  if (sort) url.searchParams.append("sort", sort);

  Object.entries(filters).forEach(([key, value]) => {
    // Define filters to exclude and check for valid values
    if (key !== "filter[search]" && value && String(value).trim() !== "") {
      url.searchParams.append(key, String(value));
    }
  });

  try {
    const response = await fetch(url.toString(), {
      headers,
    });

    return handleApiResponse(response);
  } catch (error) {
    console.error("Error fetching compliance overview metadata info:", error);
    return undefined;
  }
};

export const getComplianceAttributes = async (complianceId: string) => {
  const headers = await getAuthHeaders({ contentType: false });

  try {
    const url = new URL(`${apiBaseUrl}/compliance-overviews/attributes`);
    url.searchParams.append("filter[compliance_id]", complianceId);

    const response = await fetch(url.toString(), {
      headers,
    });

    return handleApiResponse(response);
  } catch (error) {
    console.error("Error fetching compliance attributes:", error);
    return undefined;
  }
};

export const getComplianceRequirements = async ({
  complianceId,
  scanId,
  region,
}: {
  complianceId: string;
  scanId: string;
  region?: string | string[];
}) => {
  const headers = await getAuthHeaders({ contentType: false });

  try {
    const url = new URL(`${apiBaseUrl}/compliance-overviews/requirements`);
    url.searchParams.append("filter[compliance_id]", complianceId);
    url.searchParams.append("filter[scan_id]", scanId);

    if (region) {
      const regionValue = Array.isArray(region) ? region.join(",") : region;
      url.searchParams.append("filter[region__in]", regionValue);
      //remove page param
    }
    url.searchParams.delete("page");

    const response = await fetch(url.toString(), {
      headers,
    });

    return handleApiResponse(response);
  } catch (error) {
    console.error("Error fetching compliance requirements:", error);
    return undefined;
  }
};
