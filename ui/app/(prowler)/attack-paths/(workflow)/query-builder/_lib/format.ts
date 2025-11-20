/**
 * Formatting utilities for attack path graph nodes
 */

/**
 * Format camelCase labels to space-separated text
 * e.g., "ProwlerFinding" -> "Prowler Finding", "AWSAccount" -> "Aws Account"
 */
export function formatNodeLabel(label: string): string {
  return label
    .replace(/([A-Z]+)([A-Z][a-z])/g, "$1 $2")
    .replace(/([a-z\d])([A-Z])/g, "$1 $2")
    .trim()
    .split(" ")
    .map((word) => word.charAt(0).toUpperCase() + word.slice(1).toLowerCase())
    .join(" ");
}

/**
 * Format multiple node labels into a readable string
 * e.g., ["ProwlerFinding"] -> "Prowler Finding"
 */
export function formatNodeLabels(labels: string[]): string {
  return labels.map(formatNodeLabel).join(", ");
}
