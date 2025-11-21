"use server";

import { z } from "zod";

import { apiBaseUrl, getAuthHeaders } from "@/lib";
import { handleApiResponse } from "@/lib/server-actions-helper";
import { AttackPathScan } from "@/types/attack-paths";

import { MOCK_ATTACK_PATH_SCANS } from "./mock-data";

// Validation schema for UUID - RFC 9562/4122 compliant
const UUIDSchema = z.uuid();

/**
 * Fetch list of attack path scans (latest scan for each provider)
 */
export const getAttackPathScans = async (): Promise<
  { data: AttackPathScan[] } | undefined
> => {
  // Return mock data directly for testing
  return { data: MOCK_ATTACK_PATH_SCANS };
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
