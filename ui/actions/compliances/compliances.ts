"use server";
import { revalidatePath } from "next/cache";

import { auth } from "@/auth.config";
import { apiBaseUrl, parseStringify } from "@/lib";

export const getCompliancesOverview = async ({
  scanId,
  region,
  query,
}: {
  scanId: string;
  region?: string | string[];
  query?: string;
}) => {
  const session = await auth();

  const url = new URL(`${apiBaseUrl}/compliance-overviews`);

  if (scanId) url.searchParams.append("filter[scan_id]", scanId);
  if (query) url.searchParams.append("filter[search]", query);

  if (region) {
    const regionValue = Array.isArray(region) ? region.join(",") : region;
    url.searchParams.append("filter[region__in]", regionValue);
  }

  try {
    const compliances = await fetch(url.toString(), {
      headers: {
        Accept: "application/vnd.api+json",
        Authorization: `Bearer ${session?.accessToken}`,
      },
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
  const session = await auth();

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
      headers: {
        Accept: "application/vnd.api+json",
        Authorization: `Bearer ${session?.accessToken}`,
      },
    });

    if (!response.ok) {
      throw new Error(`Failed to fetch compliance overview metadata info: ${response.statusText}`);
    }

    const parsedData = parseStringify(await response.json());

    return parsedData;
  } catch (error) {
    // eslint-disable-next-line no-console
    console.error("Error fetching compliance overview metadata info:", error);
    return undefined;
  }
};
