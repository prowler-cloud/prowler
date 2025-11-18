import { MetaDataProps } from "@/types";
import {
  AttackPathQueriesResponse,
  AttackPathQuery,
  AttackPathScan,
  AttackPathScansResponse,
} from "@/types/attack-paths";

/**
 * Adapts raw API responses to enriched domain models
 * - Transforms raw scan data with computed properties
 * - Enriches queries with metadata
 * - Co-locates related data for better performance
 * - Preserves pagination metadata for list operations
 *
 * Uses plugin architecture for extensibility:
 * - Each adapter function handles a specific response type
 * - Can be composed with backend service plugins
 * - Maintains separation of concerns between API layer and business logic
 */

/**
 * Adapt attack path scans response with enriched data
 *
 * @param response - Raw API response from attack-paths-scans endpoint
 * @returns Enriched scans data with metadata and computed properties
 */
export function adaptAttackPathScansResponse(
  response: AttackPathScansResponse | undefined,
): {
  data: AttackPathScan[];
  metadata?: MetaDataProps;
} {
  if (!response?.data) {
    return { data: [] };
  }

  // Enrich scan data with computed properties
  const enrichedData = response.data.map((scan) => ({
    ...scan,
    // Can add computed properties here, e.g.:
    // isRecent: isRecentScan(scan.attributes.completed_at),
    // durationLabel: formatDuration(scan.attributes.duration),
  }));

  // Transform links to MetaDataProps format if pagination exists
  const metadata: MetaDataProps | undefined = response.links
    ? {
        pagination: {
          // Links-based pagination doesn't have traditional page numbers
          // but we preserve the structure for consistency
          page: 1,
          pages: 1,
          count: enrichedData.length,
          itemsPerPage: [10, 25, 50, 100],
        },
        version: "1.0",
      }
    : undefined;

  return { data: enrichedData, metadata };
}

/**
 * Adapt attack path queries response with enriched data
 *
 * @param response - Raw API response from attack-paths-scans/{id}/queries endpoint
 * @returns Enriched queries data with metadata
 */
export function adaptAttackPathQueriesResponse(
  response: AttackPathQueriesResponse | undefined,
): {
  data: AttackPathQuery[];
  metadata?: MetaDataProps;
} {
  if (!response?.data) {
    return { data: [] };
  }

  // Enrich query data with computed properties
  const enrichedData = response.data.map((query) => ({
    ...query,
    // Can add computed properties here, e.g.:
    // parameterCount: query.attributes.parameters.length,
    // requiredParameters: query.attributes.parameters.filter(p => p.required),
    // hasParameters: query.attributes.parameters.length > 0,
  }));

  const metadata: MetaDataProps | undefined = {
    pagination: {
      page: 1,
      pages: 1,
      count: enrichedData.length,
      itemsPerPage: [10, 25, 50, 100],
    },
    version: "1.0",
  };

  return { data: enrichedData, metadata };
}

/**
 * Extract scan status information
 * Helper function for computing scan status with enriched information
 *
 * @param scan - Attack path scan object
 * @returns Computed status information
 */
export function getScanStatusInfo(scan: AttackPathScan): {
  status: string;
  isCompleted: boolean;
  isExecuting: boolean;
  isFailed: boolean;
  duration?: string;
  completionPercentage: number;
} {
  const { state, progress, duration } = scan.attributes;

  return {
    status: state,
    isCompleted: state === "completed",
    isExecuting: state === "executing",
    isFailed: state === "failed",
    duration: duration ? formatDuration(duration) : undefined,
    completionPercentage: progress,
  };
}

/**
 * Format duration in seconds to human-readable format
 *
 * @param seconds - Duration in seconds
 * @returns Formatted duration string (e.g., "2m 30s")
 */
function formatDuration(seconds: number): string {
  const minutes = Math.floor(seconds / 60);
  const remainingSeconds = seconds % 60;
  return `${minutes}m ${remainingSeconds}s`;
}

/**
 * Check if a scan is recent (completed within last 24 hours)
 *
 * @param completedAt - Completion timestamp
 * @returns true if scan completed within last 24 hours
 */
export function isRecentScan(completedAt: string | null): boolean {
  if (!completedAt) return false;

  const completionTime = new Date(completedAt).getTime();
  const oneDayAgo = Date.now() - 24 * 60 * 60 * 1000;

  return completionTime > oneDayAgo;
}
