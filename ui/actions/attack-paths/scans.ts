"use server";

import { z } from "zod";

import { apiBaseUrl, getAuthHeaders } from "@/lib";
import { handleApiResponse } from "@/lib/server-actions-helper";
import { AttackPathScan, AttackPathScansResponse } from "@/types/attack-paths";

import { adaptAttackPathScansResponse } from "./scans.adapter";

const UUIDSchema = z.uuid();

const ATTACK_PATH_SCANS_PAGE_SIZE = 100;
const ATTACK_PATH_SCANS_MAX_PAGES = 50;

/**
 * Fetch list of attack path scans (latest scan for each provider).
 *
 * Iterates through every backend page so callers receive the complete
 * dedup'd dataset along with an accurate total count. The underlying
 * endpoint is paginated server-side (default page_size=10), so fetching
 * only the first page would silently hide providers beyond that window.
 */
export const getAttackPathScans = async (): Promise<
  { data: AttackPathScan[] } | undefined
> => {
  const headers = await getAuthHeaders({ contentType: false });
  const allScans: AttackPathScan[] = [];
  let currentPage = 1;
  let lastResponse: AttackPathScansResponse | undefined;
  let hasMorePages = true;

  try {
    while (hasMorePages && currentPage <= ATTACK_PATH_SCANS_MAX_PAGES) {
      const url = new URL(`${apiBaseUrl}/attack-paths-scans`);
      url.searchParams.append("page[number]", currentPage.toString());
      url.searchParams.append(
        "page[size]",
        ATTACK_PATH_SCANS_PAGE_SIZE.toString(),
      );

      const response = await fetch(url.toString(), {
        headers,
        method: "GET",
      });

      const data = (await handleApiResponse(response)) as
        | AttackPathScansResponse
        | undefined;

      if (!data?.data || data.data.length === 0) {
        hasMorePages = false;
        continue;
      }

      allScans.push(...data.data);
      lastResponse = data;

      const totalPages = data.meta?.pagination?.pages ?? 1;
      if (currentPage >= totalPages) {
        hasMorePages = false;
      } else {
        currentPage++;
      }
    }

    if (!lastResponse) {
      return { data: [] };
    }

    const aggregatedResponse: AttackPathScansResponse = {
      ...lastResponse,
      data: allScans,
      meta: {
        ...lastResponse.meta,
        pagination: {
          page: 1,
          pages: 1,
          count: allScans.length,
        },
      },
    };

    const adapted = adaptAttackPathScansResponse(aggregatedResponse);

    return { data: adapted.data };
  } catch (error) {
    console.error("Error fetching attack path scans:", error);
    return undefined;
  }
};

/**
 * Fetch detail of a specific attack path scan
 */
export const getAttackPathScanDetail = async (
  scanId: string,
): Promise<{ data: AttackPathScan } | undefined> => {
  // Validate scanId is a valid UUID format to prevent request forgery
  const validatedScanId = UUIDSchema.safeParse(scanId);
  if (!validatedScanId.success) {
    console.error("Invalid scan ID format");
    return undefined;
  }

  const headers = await getAuthHeaders({ contentType: false });

  try {
    const response = await fetch(
      `${apiBaseUrl}/attack-paths-scans/${validatedScanId.data}`,
      {
        headers,
        method: "GET",
      },
    );

    return handleApiResponse(response);
  } catch (error) {
    console.error("Error fetching attack path scan detail:", error);
    return undefined;
  }
};
