export const CLOUD_UPGRADE_FEATURE = {
  ADVANCED_SCHEDULING: "advanced_scheduling",
  AI_SECURITY: "ai_security_cloud",
  ALERTS: "alerts",
  AMAZON_S3: "amazon_s3",
  API_KEYS: "api_keys",
  AWS_ORGANIZATIONS: "aws_organizations",
  AZURE_ORGANIZATIONS: "azure_organizations",
  CLI_IMPORT: "cli_import",
  CROSS_PROVIDER_COMPLIANCE: "cross_provider_compliance",
  EXPLOITABILITY_ISSUES: "exploitability_issues",
  FINDING_TRIAGE: "finding_triage",
  GCP_ORGANIZATIONS: "gcp_organizations",
  JIRA_DISPATCH: "jira_dispatch",
  LIGHTHOUSE_AI: "lighthouse_ai",
  GENERAL: "general",
  REALTIME: "realtime",
  // Distinct from the paid-plan "registry" key so both unions stay disjoint.
  REGISTRY: "registry_plugins",
  SCAN_CONFIGURATION: "scan_configuration",
  SAML_DOMAINS: "saml_domains",
} as const;

export type CloudUpgradeFeature =
  (typeof CLOUD_UPGRADE_FEATURE)[keyof typeof CLOUD_UPGRADE_FEATURE];

// Where a Local Server upgrade prompt was opened from, sent as utm_medium.
export const CLOUD_UPGRADE_SURFACE = {
  BADGE: "badge",
  FEATURE_CTA: "feature-cta",
  NUDGE: "nudge",
  OVERVIEW: "overview",
  PREMIUM_PAGE: "premium-page",
  PREVIEW_PAGE: "preview-page",
  SIDEBAR: "sidebar",
} as const;

export type CloudUpgradeSurface =
  (typeof CLOUD_UPGRADE_SURFACE)[keyof typeof CLOUD_UPGRADE_SURFACE];

// Prowler Cloud features gated behind a paid plan.
export const PAID_PLAN_UPGRADE_FEATURE = {
  AI_SECURITY: "ai_security",
  FINDINGS_PREVIEW: "findings_preview",
  REGISTRY: "registry",
  REPORT_DOWNLOAD: "report_download",
  S3_INTEGRATION: "s3_integration",
} as const;

export type PaidPlanUpgradeFeature =
  (typeof PAID_PLAN_UPGRADE_FEATURE)[keyof typeof PAID_PLAN_UPGRADE_FEATURE];

export type UpgradeFeature = CloudUpgradeFeature | PaidPlanUpgradeFeature;
