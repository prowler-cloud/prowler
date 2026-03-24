"use server";

import { z } from "zod";

import { apiBaseUrl, getAuthHeaders } from "@/lib";
import { customAttackPathQuerySchema } from "@/lib/attack-paths/custom-query";
import { handleApiResponse } from "@/lib/server-actions-helper";
import {
  AttackPathCartographySchema,
  AttackPathCartographySchemaResponse,
  AttackPathQueriesResponse,
  AttackPathQuery,
  AttackPathQueryError,
  AttackPathQueryResult,
  ExecuteCustomQueryRequest,
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
): Promise<AttackPathQueryResult | AttackPathQueryError | undefined> => {
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

    return (await handleApiResponse(response)) as
      | AttackPathQueryResult
      | AttackPathQueryError;
  } catch (error) {
    console.error("Error executing query on scan:", error);
    return {
      error:
        "Server is temporarily unavailable. Please try again in a few minutes.",
      status: 503,
    };
  }
};

/**
 * Execute a custom openCypher query on an attack path scan
 */
export const executeCustomQuery = async (
  scanId: string,
  query: string,
): Promise<AttackPathQueryResult | AttackPathQueryError | undefined> => {
  const validatedScanId = UUIDSchema.safeParse(scanId);
  if (!validatedScanId.success) {
    console.error("Invalid scan ID format");
    return undefined;
  }

  const validatedQuery = customAttackPathQuerySchema.safeParse(query);
  if (!validatedQuery.success) {
    return {
      error:
        validatedQuery.error.issues[0]?.message ?? "Custom query is invalid.",
      status: 400,
    };
  }

  const headers = await getAuthHeaders({ contentType: true });

  const requestBody: ExecuteCustomQueryRequest = {
    data: {
      type: "attack-paths-custom-query-run-requests",
      attributes: {
        query: validatedQuery.data,
      },
    },
  };

  try {
    const response = await fetch(
      `${apiBaseUrl}/attack-paths-scans/${validatedScanId.data}/queries/custom`,
      {
        headers,
        method: "POST",
        body: JSON.stringify(requestBody),
      },
    );

    return (await handleApiResponse(response)) as
      | AttackPathQueryResult
      | AttackPathQueryError;
  } catch (error) {
    console.error("Error executing custom query on scan:", error);
    return {
      error:
        "Server is temporarily unavailable. Please try again in a few minutes.",
      status: 503,
    };
  }
};

/**
 * Fetch cartography schema metadata for a specific attack path scan
 */
export const getCartographySchema = async (
  scanId: string,
): Promise<{ data: AttackPathCartographySchema } | undefined> => {
  const validatedScanId = UUIDSchema.safeParse(scanId);
  if (!validatedScanId.success) {
    console.error("Invalid scan ID format");
    return undefined;
  }

  const headers = await getAuthHeaders({ contentType: false });

  try {
    const response = await fetch(
      `${apiBaseUrl}/attack-paths-scans/${validatedScanId.data}/schema`,
      {
        headers,
        method: "GET",
      },
    );

    const apiResponse = (await handleApiResponse(
      response,
    )) as AttackPathCartographySchemaResponse;

    return { data: apiResponse.data };
  } catch (error) {
    console.error("Error fetching cartography schema for scan:", error);
    return undefined;
  }
};
