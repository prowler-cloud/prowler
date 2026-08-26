import {
  CLOUD_UPGRADE_FEATURE,
  type CloudUpgradeFeature,
} from "@/types/cloud-upgrade";
import { MAX_SAML_ADDITIONAL_EMAIL_DOMAINS } from "@/types/saml";

interface CloudUpgradeContent {
  title: string;
  description: string;
  benefits: readonly [string, string, string, ...string[]];
  primaryCta: string;
}

export const CLOUD_UPGRADE_SECONDARY_CTA = "View Plans & Pricing";
export const CLOUD_UPGRADE_FOOTER_NOTE =
  "Prowler Cloud opens in a new tab. Your Prowler Local Server remains unchanged.";

const CLOUD_SIGN_UP_URL = "https://cloud.prowler.com/sign-up";
const PRICING_URL = "https://prowler.com/pricing";
const LOCAL_SERVER_UTM_SOURCE = "prowler-local-server";

const CLOUD_UPGRADE_UTM_CONTENT = {
  [CLOUD_UPGRADE_FEATURE.ADVANCED_SCHEDULING]: "advanced-scheduling",
  [CLOUD_UPGRADE_FEATURE.ALERTS]: "alerts",
  [CLOUD_UPGRADE_FEATURE.AWS_ORGANIZATIONS]: "organization",
  [CLOUD_UPGRADE_FEATURE.AZURE_ORGANIZATIONS]: "azure-organization",
  [CLOUD_UPGRADE_FEATURE.CLI_IMPORT]: "cli-import",
  [CLOUD_UPGRADE_FEATURE.CROSS_PROVIDER_COMPLIANCE]:
    "cross-provider-compliance",
  [CLOUD_UPGRADE_FEATURE.FINDING_TRIAGE]: "findings",
  [CLOUD_UPGRADE_FEATURE.GCP_ORGANIZATIONS]: "gcp-organization",
  [CLOUD_UPGRADE_FEATURE.JIRA_DISPATCH]: "jira-dispatch",
  [CLOUD_UPGRADE_FEATURE.LIGHTHOUSE_AI]: "lighthouse-ai",
  [CLOUD_UPGRADE_FEATURE.GENERAL]: "general",
  [CLOUD_UPGRADE_FEATURE.SCAN_CONFIGURATION]: "scan-configuration",
  [CLOUD_UPGRADE_FEATURE.SAML_DOMAINS]: "saml-domains",
} as const satisfies Record<CloudUpgradeFeature, string>;

export const CLOUD_UPGRADE_CONTENT = {
  [CLOUD_UPGRADE_FEATURE.ADVANCED_SCHEDULING]: {
    title: "Keep Every Provider Checked Automatically",
    description:
      "Run scans on the cadence you choose without maintaining scheduling infrastructure.",
    benefits: [
      "Choose daily, interval, weekly, or monthly scans",
      "Set scan times in your preferred timezone",
      "Manage schedules alongside scan history",
    ],
    primaryCta: "Schedule Scans in Prowler Cloud",
  },
  [CLOUD_UPGRADE_FEATURE.ALERTS]: {
    title: "Turn Findings into Alerts",
    description:
      "Get notified when the findings you care about appear in a scan.",
    benefits: [
      "Get alerted on what matters most",
      "Notify the right people after every scan",
      "Manage alert rules from one place",
    ],
    primaryCta: "Create Alerts in Prowler Cloud",
  },
  [CLOUD_UPGRADE_FEATURE.AWS_ORGANIZATIONS]: {
    title: "Add Your Entire AWS Organization",
    description:
      "Discover accounts and organizational units, then manage them from one place.",
    benefits: [
      "Discover accounts and organizational units automatically",
      "Choose exactly which accounts to onboard",
      "Apply schedules across the selected accounts",
    ],
    primaryCta: "Set Up AWS Organizations in Prowler Cloud",
  },
  [CLOUD_UPGRADE_FEATURE.AZURE_ORGANIZATIONS]: {
    title: "Add Your Entire Azure Management Group",
    description:
      "Discover management groups and subscriptions, then manage them from one place.",
    benefits: [
      "Discover management groups and subscriptions automatically",
      "Choose exactly which subscriptions to onboard",
      "Apply schedules across the selected subscriptions",
    ],
    primaryCta: "Set Up Azure Management Groups in Prowler Cloud",
  },
  [CLOUD_UPGRADE_FEATURE.GCP_ORGANIZATIONS]: {
    title: "Add Your Entire GCP Organization",
    description:
      "Discover folders and projects, then manage them from one place.",
    benefits: [
      "Discover folders and projects automatically",
      "Choose exactly which projects to onboard",
      "Apply schedules across the selected projects",
    ],
    primaryCta: "Set Up GCP Organizations in Prowler Cloud",
  },
  [CLOUD_UPGRADE_FEATURE.CLI_IMPORT]: {
    title: "Bring CLI Findings into One Cloud View",
    description:
      "Send Prowler CLI scan results to Prowler Cloud for centralized analysis and collaboration.",
    benefits: [
      "Push results directly with --push-to-cloud",
      "Track CLI and managed scans in one place",
      "Automate findings ingestion from CI/CD pipelines",
    ],
    primaryCta: "Import CLI Findings in Prowler Cloud",
  },
  [CLOUD_UPGRADE_FEATURE.CROSS_PROVIDER_COMPLIANCE]: {
    title: "See Compliance Across Every Provider",
    description:
      "Replace separate scan reports with a consolidated compliance view.",
    benefits: [
      "Compare framework posture across providers",
      "Roll up every account in a Provider Group",
      "Find coverage gaps without switching scans",
      "Generate a consolidated compliance report",
    ],
    primaryCta: "Consolidate Compliance in Prowler Cloud",
  },
  [CLOUD_UPGRADE_FEATURE.FINDING_TRIAGE]: {
    title: "Coordinate Finding Remediation",
    description:
      "Add investigation notes and move findings through a shared remediation workflow.",
    benefits: [
      "Preserve investigation context on each finding",
      "Track review and remediation status",
      "Keep triage history with future scans",
    ],
    primaryCta: "Triage Findings in Prowler Cloud",
  },
  [CLOUD_UPGRADE_FEATURE.JIRA_DISPATCH]: {
    title: "Send Findings to Jira at Scale",
    description:
      "Create Jira issues from selected findings and finding groups without handling each item separately.",
    benefits: [
      "Send selected findings or finding groups in one action",
      "Choose between grouped and individual Jira issues",
      "Track dispatch progress and retry failed findings",
    ],
    primaryCta: "Send Findings to Jira in Prowler Cloud",
  },
  [CLOUD_UPGRADE_FEATURE.LIGHTHOUSE_AI]: {
    title: "Use The Agent Cloud Defender",
    description:
      "Investigate and act on your security posture without operating an AI stack.",
    benefits: [
      "Start without provisioning or managing OpenAI API keys",
      "Automate security workflows through the hosted remote MCP server",
      "Keep Lighthouse actions grounded in your Prowler Cloud data",
    ],
    primaryCta: "Open Lighthouse AI in Prowler Cloud",
  },
  [CLOUD_UPGRADE_FEATURE.GENERAL]: {
    title: "Scale Prowler Without Operating It",
    description:
      "Add managed automation and collaboration while Prowler operates the platform.",
    benefits: [
      "Onboard AWS Organizations and automate scans and alerts",
      "Triage findings and consolidate compliance across providers",
      "Investigate and remediate with Lighthouse AI and Agentic View",
      "Use managed infrastructure, support, and backups",
    ],
    primaryCta: "Start a Prowler Cloud Trial",
  },
  [CLOUD_UPGRADE_FEATURE.SCAN_CONFIGURATION]: {
    title: "Configure Every Scan Once",
    description:
      "Create reusable scan configurations instead of rebuilding options for each run.",
    benefits: [
      "Reduce noise by fine-tuning scan configurations",
      "Apply consistent configurations to providers",
      "Manage scan behavior from one place",
    ],
    primaryCta: "Configure Scans in Prowler Cloud",
  },
  [CLOUD_UPGRADE_FEATURE.SAML_DOMAINS]: {
    title: "Use One SAML Configuration Across Domains",
    description:
      "Let users from multiple verified email domains share one SAML identity provider configuration.",
    benefits: [
      "Keep one primary domain and canonical ACS URL",
      `Authorize up to ${MAX_SAML_ADDITIONAL_EMAIL_DOMAINS} additional email domains`,
      "Manage every domain from the same SAML configuration",
    ],
    primaryCta: "Manage SAML Domains in Prowler Cloud",
  },
} as const satisfies Record<CloudUpgradeFeature, CloudUpgradeContent>;

const buildCloudUpgradeUrl = (
  baseUrl: string,
  feature: CloudUpgradeFeature,
) => {
  const url = new URL(baseUrl);
  url.searchParams.set("utm_source", LOCAL_SERVER_UTM_SOURCE);
  url.searchParams.set("utm_content", CLOUD_UPGRADE_UTM_CONTENT[feature]);

  return url.toString();
};

export const getCloudUpgradePrimaryUrl = (feature: CloudUpgradeFeature) =>
  buildCloudUpgradeUrl(CLOUD_SIGN_UP_URL, feature);

export const getCloudUpgradeCompareUrl = (feature: CloudUpgradeFeature) =>
  buildCloudUpgradeUrl(PRICING_URL, feature);
