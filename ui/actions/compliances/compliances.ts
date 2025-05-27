"use server";
import { revalidatePath } from "next/cache";

import { apiBaseUrl, getAuthHeaders, parseStringify } from "@/lib";

export const getCompliancesOverview = async ({
  scanId,
  region,
  query,
}: {
  scanId: string;
  region?: string | string[];
  query?: string;
}) => {
  const headers = await getAuthHeaders({ contentType: false });

  const url = new URL(`${apiBaseUrl}/compliance-overviews`);

  if (scanId) url.searchParams.append("filter[scan_id]", scanId);
  if (query) url.searchParams.append("filter[search]", query);

  if (region) {
    const regionValue = Array.isArray(region) ? region.join(",") : region;
    url.searchParams.append("filter[region__in]", regionValue);
  }

  try {
    const compliances = await fetch(url.toString(), {
      headers,
    });
    const data = await compliances.json();
    const parsedData = parseStringify(data);
    revalidatePath("/compliance");
    return parsedData;
  } catch (error) {
    // eslint-disable-next-line no-console
    console.error("Error fetching providers:", error);
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
    // Define filters to exclude
    if (key !== "filter[search]") {
      url.searchParams.append(key, String(value));
    }
  });

  try {
    const response = await fetch(url.toString(), {
      headers,
    });

    if (!response.ok) {
      throw new Error(
        `Failed to fetch compliance overview metadata info: ${response.statusText}`,
      );
    }

    const parsedData = parseStringify(await response.json());

    return parsedData;
  } catch (error) {
    // eslint-disable-next-line no-console
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

    if (!response.ok) {
      throw new Error(
        `Failed to fetch compliance attributes: ${response.statusText}`,
      );
    }

    const data = await response.json();

    const parsedData = parseStringify(data);
    return parsedData;
  } catch (error) {
    // eslint-disable-next-line no-console
    console.error("Error fetching compliance attributes:", error);
    return undefined;
  }
  // */
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

    if (!response.ok) {
      throw new Error(
        `Failed to fetch compliance requirements: ${response.statusText}`,
      );
    }

    const data = await response.json();
    const parsedData = parseStringify(data);

    return parsedData;
  } catch (error) {
    // eslint-disable-next-line no-console
    console.error("Error fetching compliance requirements:", error);
    return undefined;
  }
  // */
};
