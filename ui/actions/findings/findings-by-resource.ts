"use server";

import { apiBaseUrl, getAuthHeaders } from "@/lib";
import { handleApiResponse } from "@/lib/server-actions-helper";

/**
 * Resolves resource UIDs + check ID into actual finding UUIDs.
 * Uses /findings/latest with check_id and resource_uid__in filters
 * to batch-resolve in a single API call.
 */
export const resolveFindingIds = async ({
  checkId,
  resourceUids,
}: {
  checkId: string;
  resourceUids: string[];
}): Promise<string[]> => {
  const headers = await getAuthHeaders({ contentType: false });

  const url = new URL(`${apiBaseUrl}/findings/latest`);
  url.searchParams.append("filter[check_id]", checkId);
  url.searchParams.append("filter[resource_uid__in]", resourceUids.join(","));
  url.searchParams.append("filter[muted]", "false");
  url.searchParams.append("page[size]", resourceUids.length.toString());

  try {
    const response = await fetch(url.toString(), { headers });
    const data = await handleApiResponse(response);

    if (!data?.data || !Array.isArray(data.data)) return [];

    return data.data.map((item: { id: string }) => item.id);
  } catch (error) {
    console.error("Error resolving finding IDs:", error);
    return [];
  }
};

/**
 * Resolves check IDs into actual finding UUIDs.
 * Used at the group level where each row represents a check_id.
 */
export const resolveFindingIdsByCheckIds = async ({
  checkIds,
}: {
  checkIds: string[];
}): Promise<string[]> => {
  const headers = await getAuthHeaders({ contentType: false });

  const url = new URL(`${apiBaseUrl}/findings/latest`);
  url.searchParams.append("filter[check_id__in]", checkIds.join(","));
  url.searchParams.append("filter[muted]", "false");
  // TODO: If a check group has >500 non-muted findings, this silently truncates
  // the resolved IDs. Consider paginating or surfacing a warning to the user.
  url.searchParams.append("page[size]", "500");

  try {
    const response = await fetch(url.toString(), { headers });
    const data = await handleApiResponse(response);

    if (!data?.data || !Array.isArray(data.data)) return [];

    return data.data.map((item: { id: string }) => item.id);
  } catch (error) {
    console.error("Error resolving finding IDs by check IDs:", error);
    return [];
  }
};

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
