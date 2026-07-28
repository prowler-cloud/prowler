export const LIGHTHOUSE_CONTEXT_KIND = {
  PAGE: "page",
  FINDING: "finding",
  RESOURCE: "resource",
  COMPLIANCE: "compliance",
  ATTACK_PATH: "attack_path",
  SCAN: "scan",
  PROVIDER: "provider",
} as const;

export const LIGHTHOUSE_CONTEXT_SOURCE = {
  AUTOMATIC: "automatic",
  FOCUSED: "focused",
  SELECTION: "selection",
  MANUAL: "manual",
} as const;

export const LIGHTHOUSE_CONTEXT_TRANSPORT = {
  INLINE: "inline",
} as const;

export const LIGHTHOUSE_CONTEXT_LIMIT = {
  STRING_LENGTH: 256,
  FILTER_VALUES: 20,
  ITEMS: 8,
  ATTACK_PATH_PARAMETERS: 8,
} as const;

export const LIGHTHOUSE_PAGE_ID = {
  OVERVIEW: "overview",
  FINDINGS: "findings",
  RESOURCES: "resources",
  COMPLIANCE: "compliance",
  COMPLIANCE_DETAIL: "compliance-detail",
  ATTACK_PATHS: "attack-paths",
  SCANS: "scans",
  PROVIDERS: "providers",
  OTHER: "other",
} as const;
