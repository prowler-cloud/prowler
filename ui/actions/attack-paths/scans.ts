"use server";

import { z } from "zod";

import { apiBaseUrl, getAuthHeaders } from "@/lib";
import { handleApiResponse } from "@/lib/server-actions-helper";
import { AttackPathScan, AttackPathScansResponse } from "@/types/attack-paths";

// Validation schema for UUID
const UUIDSchema = z.string().uuid();

/**
 * Fetch list of attack path scans (latest scan for each provider)
 */
export const getAttackPathScans = async (): Promise<
  AttackPathScansResponse | undefined
> => {
  const headers = await getAuthHeaders({ contentType: false });

  try {
    const response = await fetch(`${apiBaseUrl}/attack-paths-scans`, {
      headers,
      method: "GET",
    });

    return handleApiResponse(response);
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
    const response = await fetch(`${apiBaseUrl}/attack-paths-scans/${scanId}`, {
      headers,
      method: "GET",
    });

    return handleApiResponse(response);
  } catch (error) {
    console.error(
      `Error fetching attack path scan detail for ${scanId}:`,
      error,
    );
    return undefined;
  }
};
