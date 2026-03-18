"use server";

import { apiBaseUrl, getAuthHeaders } from "@/lib";
import { handleApiResponse } from "@/lib/server-actions-helper";

export const getLatestFindingsByResourceUid = async ({
  resourceUid,
  page = 1,
  pageSize = 50,
}: {
  resourceUid: string;
  page?: number;
  pageSize?: number;
}) => {
  const headers = await getAuthHeaders({ contentType: false });

  const url = new URL(
    `${apiBaseUrl}/findings/latest?include=resources,scan.provider`,
  );

  url.searchParams.append("filter[resource_uid]", resourceUid);
  if (page) url.searchParams.append("page[number]", page.toString());
  if (pageSize) url.searchParams.append("page[size]", pageSize.toString());

  try {
    const findings = await fetch(url.toString(), {
      headers,
    });

    return handleApiResponse(findings);
  } catch (error) {
    console.error("Error fetching findings by resource UID:", error);
    return undefined;
  }
};
