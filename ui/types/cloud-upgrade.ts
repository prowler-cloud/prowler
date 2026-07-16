export const CLOUD_UPGRADE_FEATURE = {
  ADVANCED_SCHEDULING: "advanced_scheduling",
  ALERTS: "alerts",
  AWS_ORGANIZATIONS: "aws_organizations",
  CLI_IMPORT: "cli_import",
  CROSS_PROVIDER_COMPLIANCE: "cross_provider_compliance",
  FINDING_TRIAGE: "finding_triage",
  LIGHTHOUSE_AI: "lighthouse_ai",
  GENERAL: "general",
  SCAN_CONFIGURATION: "scan_configuration",
} as const;

export type CloudUpgradeFeature =
  (typeof CLOUD_UPGRADE_FEATURE)[keyof typeof CLOUD_UPGRADE_FEATURE];
