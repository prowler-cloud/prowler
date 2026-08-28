export const LIGHTHOUSE_CONTEXT_KIND = {
  PAGE: "page",
  FINDING: "finding",
  RESOURCE: "resource",
  COMPLIANCE: "compliance",
  ATTACK_PATH: "attack_path",
  SCAN: "scan",
  PROVIDER: "provider",
  ALERT: "alert",
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
  ITEMS: 12,
  SEVERITY_COUNTS: 5,
  ATTACK_PATH_PARAMETERS: 8,
  ATTACK_PATH_REDACTED_PARAMETERS: 8,
  ATTACK_PATH_TYPE_COUNTS: 12,
} as const;

export const LIGHTHOUSE_CONTEXT_CONTRIBUTOR_LIMIT = {
  AFTER_PAGE: LIGHTHOUSE_CONTEXT_LIMIT.ITEMS - 1,
  AFTER_PAGE_AND_SUMMARY: LIGHTHOUSE_CONTEXT_LIMIT.ITEMS - 2,
} as const;

export const LIGHTHOUSE_COMPLIANCE_CONTEXT_MODE = {
  PER_SCAN: "per-scan",
  CROSS_PROVIDER: "cross-provider",
  CROSS_ACCOUNT: "cross-account",
} as const;

export type LighthouseComplianceContextMode =
  (typeof LIGHTHOUSE_COMPLIANCE_CONTEXT_MODE)[keyof typeof LIGHTHOUSE_COMPLIANCE_CONTEXT_MODE];

export const LIGHTHOUSE_PAGE_ID = {
  OVERVIEW: "overview",
  FINDINGS: "findings",
  RESOURCES: "resources",
  COMPLIANCE: "compliance",
  COMPLIANCE_DETAIL: "compliance-detail",
  ATTACK_PATHS: "attack-paths",
  SCANS: "scans",
  PROVIDERS: "providers",
  ALERTS: "alerts",
  SERVICES: "services",
  WORKLOADS: "workloads",
  MUTELIST: "mutelist",
  ROLES: "roles",
  USERS: "users",
  INVITATIONS: "invitations",
  INTEGRATIONS: "integrations",
  OTHER: "other",
} as const;
