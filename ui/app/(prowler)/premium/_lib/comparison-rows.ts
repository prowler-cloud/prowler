import {
  CLOUD_UPGRADE_FEATURE,
  type CloudUpgradeFeature,
} from "@/types/cloud-upgrade";

type EditionAvailability = boolean | string;

interface PremiumComparisonRow {
  capability: string;
  localServer: EditionAvailability;
  cloud: EditionAvailability;
  privateCloud: EditionAvailability;
  // Where a Local Server user can see the capability: a preview route or the upgrade modal.
  href?: string;
  feature?: CloudUpgradeFeature;
}

const PREMIUM = { localServer: false, cloud: true, privateCloud: true };
const EVERYWHERE = { localServer: true, cloud: true, privateCloud: true };

export const PREMIUM_COMPARISON_ROWS: readonly PremiumComparisonRow[] = [
  {
    capability: "Scans, checks, compliance frameworks, and Mutelist",
    ...EVERYWHERE,
  },
  { capability: "Lighthouse AI with your own LLM key", ...EVERYWHERE },
  { capability: "Attack Paths (AWS)", ...EVERYWHERE },
  {
    capability: "Exploitability Issues and emerging threats",
    ...PREMIUM,
    href: "/issues",
  },
  {
    capability: "Realtime (CloudTrail detection and auto-fix)",
    ...PREMIUM,
    href: "/realtime",
  },
  {
    capability: "Alerts",
    ...PREMIUM,
    feature: CLOUD_UPGRADE_FEATURE.ALERTS,
  },
  {
    capability: "Advanced scan scheduling",
    ...PREMIUM,
    feature: CLOUD_UPGRADE_FEATURE.ADVANCED_SCHEDULING,
  },
  {
    capability: "Organization onboarding (AWS, Azure, GCP)",
    ...PREMIUM,
    feature: CLOUD_UPGRADE_FEATURE.AWS_ORGANIZATIONS,
  },
  {
    capability: "Finding triage and notes",
    ...PREMIUM,
    feature: CLOUD_UPGRADE_FEATURE.FINDING_TRIAGE,
  },
  {
    capability: "Cross-provider compliance and consolidated reports",
    ...PREMIUM,
    feature: CLOUD_UPGRADE_FEATURE.CROSS_PROVIDER_COMPLIANCE,
  },
  {
    capability: "Registry (third-party checks, frameworks, and providers)",
    ...PREMIUM,
    feature: CLOUD_UPGRADE_FEATURE.REGISTRY,
  },
  {
    capability: "Managed Lighthouse AI and remote MCP server",
    ...PREMIUM,
    feature: CLOUD_UPGRADE_FEATURE.LIGHTHOUSE_AI,
  },
  {
    capability: "Scan configurations",
    ...PREMIUM,
    feature: CLOUD_UPGRADE_FEATURE.SCAN_CONFIGURATION,
  },
  {
    capability: "Import findings from the Prowler CLI",
    ...PREMIUM,
    feature: CLOUD_UPGRADE_FEATURE.CLI_IMPORT,
  },
  {
    capability: "Amazon S3 export",
    ...PREMIUM,
    feature: CLOUD_UPGRADE_FEATURE.AMAZON_S3,
  },
  {
    capability: "API keys",
    ...PREMIUM,
    feature: CLOUD_UPGRADE_FEATURE.API_KEYS,
  },
  {
    capability: "Bulk and grouped Jira dispatch",
    ...PREMIUM,
    feature: CLOUD_UPGRADE_FEATURE.JIRA_DISPATCH,
  },
  {
    capability: "SAML with additional email domains",
    ...PREMIUM,
    feature: CLOUD_UPGRADE_FEATURE.SAML_DOMAINS,
  },
  {
    capability: "Hosting and operations",
    localServer: "You",
    cloud: "Prowler",
    privateCloud: "Your cloud",
  },
  {
    capability: "Support",
    localServer: "Community",
    cloud: "Enterprise",
    privateCloud: "Enterprise",
  },
];
