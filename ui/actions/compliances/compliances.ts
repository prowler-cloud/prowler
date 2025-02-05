"use server";
import { revalidatePath } from "next/cache";

import { auth } from "@/auth.config";
import { parseStringify } from "@/lib";

export const getCompliancesOverview = async ({
  scanId,
  region,
}: {
  scanId: string;
  region?: string | string[];
}) => {
  const session = await auth();

  const keyServer = process.env.API_BASE_URL;
  const url = new URL(`${keyServer}/compliance-overviews`);

  if (scanId) url.searchParams.append("filter[scan_id]", scanId);

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
