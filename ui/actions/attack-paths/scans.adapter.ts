import { MetaDataProps } from "@/types";
import { AttackPathScan, AttackPathScansResponse } from "@/types/attack-paths";

/**
 * Adapts raw scan API responses to enriched domain models
 * - Transforms raw scan data with computed properties
 * - Co-locates related data for better performance
 * - Preserves pagination metadata for list operations
 *
 * Uses plugin architecture for extensibility:
 * - Handles scan-specific response transformation
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
    attributes: {
      ...scan.attributes,
      // Format duration for display
      durationLabel: scan.attributes.duration
        ? formatDuration(scan.attributes.duration)
        : null,
      // Check if scan is recent (completed within last 24 hours)
      isRecent: isRecentScan(scan.attributes.completed_at),
    },
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
function isRecentScan(completedAt: string | null): boolean {
  if (!completedAt) return false;

  const completionTime = new Date(completedAt).getTime();
  const oneDayAgo = Date.now() - 24 * 60 * 60 * 1000;

  return completionTime > oneDayAgo;
}
