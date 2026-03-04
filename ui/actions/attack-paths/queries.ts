"use server";

import { z } from "zod";

import { apiBaseUrl, getAuthHeaders } from "@/lib";
import { handleApiResponse } from "@/lib/server-actions-helper";
import {
  AttackPathQueriesResponse,
  AttackPathQuery,
  AttackPathQueryResult,
  ExecuteQueryRequest,
} from "@/types/attack-paths";

import { adaptAttackPathQueriesResponse } from "./queries.adapter";

// Validation schema for UUID - RFC 9562/4122 compliant
const UUIDSchema = z.uuid();

/**
 * Fetch available queries for a specific attack path scan
 */
export const getAvailableQueries = async (
  scanId: string,
): Promise<{ data: AttackPathQuery[] } | undefined> => {
  // Validate scanId is a valid UUID format to prevent request forgery
  const validatedScanId = UUIDSchema.safeParse(scanId);
  if (!validatedScanId.success) {
    console.error("Invalid scan ID format");
    return undefined;
  }

  const headers = await getAuthHeaders({ contentType: false });

  try {
    const response = await fetch(
      `${apiBaseUrl}/attack-paths-scans/${validatedScanId.data}/queries`,
      {
        headers,
        method: "GET",
      },
    );

    const apiResponse = (await handleApiResponse(
      response,
    )) as AttackPathQueriesResponse;
    const adaptedData = adaptAttackPathQueriesResponse(apiResponse);

    return { data: adaptedData.data };
  } catch (error) {
    console.error("Error fetching available queries for scan:", error);
    return undefined;
  }
};

/**
 * Execute a query on an attack path scan
 */
export const executeQuery = async (
  scanId: string,
  queryId: string,
  parameters?: Record<string, string | number | boolean>,
): Promise<AttackPathQueryResult | undefined> => {
  // Validate scanId is a valid UUID format to prevent request forgery
  const validatedScanId = UUIDSchema.safeParse(scanId);
  if (!validatedScanId.success) {
    console.error("Invalid scan ID format");
    return undefined;
  }

  const headers = await getAuthHeaders({ contentType: true });

  const requestBody: ExecuteQueryRequest = {
    data: {
      type: "attack-paths-query-run-requests",
      attributes: {
        id: queryId,
        ...(parameters && { parameters }),
      },
    },
  };

  try {
    const response = await fetch(
      `${apiBaseUrl}/attack-paths-scans/${validatedScanId.data}/queries/run`,
      {
        headers,
        method: "POST",
        body: JSON.stringify(requestBody),
      },
    );

    return handleApiResponse(response);
  } catch (error) {
    console.error("Error executing query on scan:", error);
    return undefined;
  }
};
