"use server";

import { AttackPathQuery, AttackPathQueryResult } from "@/types/attack-paths";

import { MOCK_ATTACK_PATH_QUERIES, MOCK_QUERY_RESULT_DATA } from "./mock-data";

/**
 * Fetch available queries for a specific attack path scan
 */
export const getAvailableQueries = async (
  _scanId: string,
): Promise<{ data: AttackPathQuery[] } | undefined> => {
  // Return mock data directly for testing
  return { data: MOCK_ATTACK_PATH_QUERIES };
};

/**
 * Execute a query on an attack path scan
 */
export const executeQuery = async (
  _scanId: string,
  _queryId: string,
  _parameters?: Record<string, string | number | boolean>,
): Promise<AttackPathQueryResult | undefined> => {
  // Return mock data directly for testing
  return {
    data: {
      type: "attack-paths-query-run-request",
      id: null,
      attributes: MOCK_QUERY_RESULT_DATA,
    },
  };
};
