/**
 * Converts a category ID to a human-readable label.
 * Capitalizes each word and replaces hyphens with spaces.
 *
 * Examples:
 * - "internet-exposed" -> "Internet Exposed"
 * - "iam" -> "Iam"
 * - "forensics-ready" -> "Forensics Ready"
 */
export function getCategoryLabel(id: string): string {
  return id
    .split("-")
    .map((word) => word.charAt(0).toUpperCase() + word.slice(1))
    .join(" ");
}
