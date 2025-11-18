"use server";

import { apiBaseUrl, getAuthHeaders } from "@/lib";
import { handleApiResponse } from "@/lib/server-actions-helper";
import {
  AttackPathQueriesResponse,
  AttackPathQueryResult,
  ExecuteQueryRequest,
} from "@/types/attack-paths";

/**
 * Fetch available queries for a specific attack path scan
 */
export const getAvailableQueries = async (
  scanId: string,
): Promise<AttackPathQueriesResponse | undefined> => {
  const headers = await getAuthHeaders({ contentType: false });

  try {
    const response = await fetch(
      `${apiBaseUrl}/attack-paths-scans/${scanId}/queries`,
      {
        headers,
        method: "GET",
      },
    );

    return handleApiResponse(response);
  } catch (error) {
    console.error(
      `Error fetching available queries for scan ${scanId}:`,
      error,
    );
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
  const headers = await getAuthHeaders({ contentType: true });

  const requestBody: ExecuteQueryRequest = {
    data: {
      type: "attack-paths-query-run-request",
      attributes: {
        id: queryId,
        ...(parameters && { parameters }),
      },
    },
  };

  try {
    const response = await fetch(
      `${apiBaseUrl}/attack-paths-scans/${scanId}/queries/run`,
      {
        headers,
        method: "POST",
        body: JSON.stringify(requestBody),
      },
    );

    return handleApiResponse(response);
  } catch (error) {
    console.error(`Error executing query ${queryId} on scan ${scanId}:`, error);
    return undefined;
  }
};
