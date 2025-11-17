"use server";

import { apiBaseUrl, getAuthHeaders } from "@/lib";
import {
  mockGraphQueryResult,
  mockQueriesResponse,
  mockScansResponse,
} from "@/lib/attack-paths/mock-data";
import { handleApiResponse } from "@/lib/server-actions-helper";
import {
  AttackPathQueriesResponse,
  AttackPathQueryResult,
  AttackPathScan,
  AttackPathScansResponse,
  ExecuteQueryRequest,
} from "@/types/attack-paths";

// Flag to enable/disable mock data for development
const USE_MOCK_DATA = process.env.NEXT_PUBLIC_USE_MOCK_ATTACK_PATHS === "true";

/**
 * Fetch list of attack path scans (latest scan for each provider)
 */
export const getAttackPathScans = async (): Promise<
  AttackPathScansResponse | undefined
> => {
  if (USE_MOCK_DATA) {
    return mockScansResponse;
  }

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

/**
 * Fetch available queries for a specific attack path scan
 */
export const getAvailableQueries = async (
  scanId: string,
): Promise<AttackPathQueriesResponse | undefined> => {
  if (USE_MOCK_DATA) {
    return mockQueriesResponse;
  }

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
  if (USE_MOCK_DATA) {
    // Simulate network delay
    await new Promise((resolve) => setTimeout(resolve, 800));
    return mockGraphQueryResult;
  }

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
