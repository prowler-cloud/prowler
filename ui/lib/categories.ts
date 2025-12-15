// Category IDs from the API
export const CATEGORY_IDS = {
  E3: "e3",
  E5: "e5",
  ENCRYPTION: "encryption",
  FORENSICS_READY: "forensics-ready",
  IAM: "iam",
  INTERNET_EXPOSED: "internet-exposed",
  LOGGING: "logging",
  NETWORK: "network",
  PUBLICLY_ACCESSIBLE: "publicly-accessible",
  SECRETS: "secrets",
  STORAGE: "storage",
  THREAT_DETECTION: "threat-detection",
  TRUSTBOUNDARIES: "trustboundaries",
  UNUSED: "unused",
} as const;

export type CategoryId = (typeof CATEGORY_IDS)[keyof typeof CATEGORY_IDS];

// Human-readable labels for category IDs
export const CATEGORY_LABELS: Record<string, string> = {
  [CATEGORY_IDS.E3]: "E3",
  [CATEGORY_IDS.E5]: "E5",
  [CATEGORY_IDS.ENCRYPTION]: "Encryption",
  [CATEGORY_IDS.FORENSICS_READY]: "Forensics Ready",
  [CATEGORY_IDS.IAM]: "IAM",
  [CATEGORY_IDS.INTERNET_EXPOSED]: "Internet Exposed",
  [CATEGORY_IDS.LOGGING]: "Logging",
  [CATEGORY_IDS.NETWORK]: "Network",
  [CATEGORY_IDS.PUBLICLY_ACCESSIBLE]: "Publicly Accessible",
  [CATEGORY_IDS.SECRETS]: "Secrets",
  [CATEGORY_IDS.STORAGE]: "Storage",
  [CATEGORY_IDS.THREAT_DETECTION]: "Threat Detection",
  [CATEGORY_IDS.TRUSTBOUNDARIES]: "Trust Boundaries",
  [CATEGORY_IDS.UNUSED]: "Unused",
};

/**
 * Converts a category ID to a human-readable label.
 * Falls back to capitalizing the ID if not found in the mapping.
 */
export function getCategoryLabel(id: string): string {
  if (CATEGORY_LABELS[id]) {
    return CATEGORY_LABELS[id];
  }
  // Fallback: capitalize and replace hyphens with spaces
  return id
    .split("-")
    .map((word) => word.charAt(0).toUpperCase() + word.slice(1))
    .join(" ");
}
