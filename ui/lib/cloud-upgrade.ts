import { PRICING_URL } from "@/lib/external-urls";
import {
  CLOUD_UPGRADE_FEATURE,
  CLOUD_UPGRADE_SURFACE,
  type CloudUpgradeFeature,
  type CloudUpgradeSurface,
  PAID_PLAN_UPGRADE_FEATURE,
  type PaidPlanUpgradeFeature,
  type UpgradeFeature,
} from "@/types/cloud-upgrade";
import { MAX_SAML_ADDITIONAL_EMAIL_DOMAINS } from "@/types/saml";

import { FINDINGS_PREVIEW_ROW_LIMIT } from "./findings-access";

interface UpgradeContent {
  title: string;
  description: string;
  benefits: readonly [string, string, string, ...string[]];
}

interface CloudUpgradeContent extends UpgradeContent {
  // Whether the Prowler Cloud free trial unlocks this capability.
  trialIncluded: boolean;
}

interface PaidPlanUpgradeContent extends UpgradeContent {
  primaryCta: string;
}

export const PREMIUM_BADGE_LABEL = "Cloud & Private Cloud";
export const PREMIUM_BADGE_COMPACT_LABEL = "Premium";
export const PREMIUM_BADGE_TOOLTIP =
  "Premium feature. Click to see what it does in Prowler Cloud and Private Cloud.";

const CLOUD_UPGRADE_TRIAL_CTA = "Start a 7-day free trial";
const CLOUD_UPGRADE_TRIAL_NOTE = "No credit card required.";
const CLOUD_UPGRADE_PLANS_CTA = "See plans";
const CLOUD_UPGRADE_PLANS_NOTE =
  "Included in paid plans. The free trial covers the rest of Prowler Cloud.";
export const CLOUD_UPGRADE_SALES_CTA = "Talk to sales about Private Cloud";
export const CLOUD_UPGRADE_SECONDARY_CTA = "View Plans & Pricing";
export const CLOUD_UPGRADE_COMPARE_CTA = "Compare plans";
export const CLOUD_UPGRADE_FOOTER_NOTE =
  "Prowler Cloud and Private Cloud run the same engine as your Local Server. Your Local Server stays unchanged.";

const CLOUD_SIGN_UP_URL = "https://cloud.prowler.com/sign-up";
const PRIVATE_CLOUD_CONTACT_URL = "https://prowler.com/contact";
const LOCAL_SERVER_UTM_SOURCE = "prowler-local-server";

const CLOUD_UPGRADE_UTM_CONTENT = {
  [CLOUD_UPGRADE_FEATURE.ADVANCED_SCHEDULING]: "advanced-scheduling",
  [CLOUD_UPGRADE_FEATURE.AI_SECURITY]: "ai-security",
  [CLOUD_UPGRADE_FEATURE.ALERTS]: "alerts",
  [CLOUD_UPGRADE_FEATURE.AMAZON_S3]: "amazon-s3",
  [CLOUD_UPGRADE_FEATURE.API_KEYS]: "api-keys",
  [CLOUD_UPGRADE_FEATURE.AWS_ORGANIZATIONS]: "aws-organization",
  [CLOUD_UPGRADE_FEATURE.AZURE_ORGANIZATIONS]: "azure-organization",
  [CLOUD_UPGRADE_FEATURE.CLI_IMPORT]: "cli-import",
  [CLOUD_UPGRADE_FEATURE.CROSS_PROVIDER_COMPLIANCE]:
    "cross-provider-compliance",
  [CLOUD_UPGRADE_FEATURE.EXPLOITABILITY_ISSUES]: "exploitability-issues",
  [CLOUD_UPGRADE_FEATURE.FINDING_TRIAGE]: "finding-triage",
  [CLOUD_UPGRADE_FEATURE.GCP_ORGANIZATIONS]: "gcp-organization",
  [CLOUD_UPGRADE_FEATURE.JIRA_DISPATCH]: "jira-dispatch",
  [CLOUD_UPGRADE_FEATURE.LIGHTHOUSE_AI]: "lighthouse-ai",
  [CLOUD_UPGRADE_FEATURE.GENERAL]: "general",
  [CLOUD_UPGRADE_FEATURE.REALTIME]: "realtime",
  [CLOUD_UPGRADE_FEATURE.REGISTRY]: "registry",
  [CLOUD_UPGRADE_FEATURE.SCAN_CONFIGURATION]: "scan-configuration",
  [CLOUD_UPGRADE_FEATURE.SAML_DOMAINS]: "saml-domains",
} as const satisfies Record<CloudUpgradeFeature, string>;

const AMAZON_S3_BENEFITS = [
  "Export findings after each scan",
  "Choose the providers and output folder per bucket",
  "Authenticate with an IAM role or static credentials",
] as const;

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
    trialIncluded: false,
  },
  [CLOUD_UPGRADE_FEATURE.AI_SECURITY]: {
    title: "See the Security of Your AI Stack",
    description:
      "One view of how your AI vendors, cloud AI services and AI workflows are configured.",
    benefits: [
      "Scan Claude, OpenAI and ChatGPT organizations next to your cloud accounts",
      "Score them against OWASP LLM Top 10 and the other AI frameworks",
      "Start from the riskiest AI findings across every provider",
    ],
    trialIncluded: true,
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
    trialIncluded: true,
  },
  [CLOUD_UPGRADE_FEATURE.AMAZON_S3]: {
    title: "Export Findings to Amazon S3",
    description:
      "Send every scan's results to your own S3 buckets automatically. Existing S3 integrations keep working.",
    benefits: AMAZON_S3_BENEFITS,
    trialIncluded: false,
  },
  [CLOUD_UPGRADE_FEATURE.API_KEYS]: {
    title: "Automate Prowler with API Keys",
    description:
      "Give scripts, pipelines, and integrations programmatic access to Prowler.",
    benefits: [
      "Create named keys with their own expiration",
      "Revoke a key without touching your user account",
      "See when each key was last used",
    ],
    trialIncluded: true,
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
    trialIncluded: true,
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
    trialIncluded: true,
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
    trialIncluded: true,
  },
  [CLOUD_UPGRADE_FEATURE.CLI_IMPORT]: {
    title: "Bring CLI Findings into One View",
    description:
      "Send Prowler CLI scan results to Prowler for centralized analysis and collaboration.",
    benefits: [
      "Push results directly with --push-to-cloud",
      "Track CLI and managed scans in one place",
      "Automate findings ingestion from CI/CD pipelines",
    ],
    trialIncluded: false,
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
    trialIncluded: true,
  },
  [CLOUD_UPGRADE_FEATURE.EXPLOITABILITY_ISSUES]: {
    title: "Fix What an Attacker Can Actually Exploit",
    description:
      "Exploitability Issues groups related findings into attack patterns, adds a verdict on how exploitable each one is, and flags instances that match emerging threats.",
    benefits: [
      "Turn hundreds of findings into a short list of attack patterns",
      "Rank each issue by how exploitable it is",
      "Spot resources exposed to emerging threats",
    ],
    trialIncluded: true,
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
    trialIncluded: false,
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
    trialIncluded: true,
  },
  [CLOUD_UPGRADE_FEATURE.LIGHTHOUSE_AI]: {
    title: "Use Managed Lighthouse AI",
    description:
      "Investigate and act on your security posture without operating an AI stack.",
    benefits: [
      "Start without provisioning or managing LLM API keys",
      "Automate security workflows through the hosted remote MCP server",
      "Keep sessions and context grounded in your Prowler data",
    ],
    trialIncluded: true,
  },
  [CLOUD_UPGRADE_FEATURE.GENERAL]: {
    title: "Scale Prowler Without Operating It",
    description:
      "Prowler Cloud and Private Cloud add premium capabilities on top of the open source engine you already run.",
    benefits: [
      "Prioritize with Exploitability Issues and catch risky AWS changes with Realtime",
      "Onboard AWS, Azure, and GCP organizations and automate scans and alerts",
      "Triage findings and consolidate compliance across providers",
      "Export to Amazon S3, automate with API keys, and use Managed Lighthouse AI",
      "Get managed operations, enterprise support, and backups",
    ],
    trialIncluded: true,
  },
  [CLOUD_UPGRADE_FEATURE.REALTIME]: {
    title: "Catch Risky AWS Changes as They Happen",
    description:
      "Prowler Realtime watches CloudTrail and responds minutes after a change, not at the next scan.",
    benefits: [
      "Check each risky event against the resource it touched",
      "Alert, propose a Terraform pull request, or fix it automatically",
      "Review and revert every automatic fix",
    ],
    trialIncluded: true,
  },
  [CLOUD_UPGRADE_FEATURE.REGISTRY]: {
    title: "Extend Prowler with Registry",
    description:
      "Add third-party checks, compliance frameworks, and providers published in Prowler Registry.",
    benefits: [
      "Connect custom cloud providers",
      "Extend your assessments with custom security checks",
      "Use private compliance frameworks across your accounts",
    ],
    trialIncluded: false,
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
    trialIncluded: true,
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
    trialIncluded: true,
  },
} as const satisfies Record<CloudUpgradeFeature, CloudUpgradeContent>;

const buildCloudUpgradeUrl = (
  baseUrl: string,
  feature: CloudUpgradeFeature,
  surface: CloudUpgradeSurface,
) => {
  const url = new URL(baseUrl);
  url.searchParams.set("utm_source", LOCAL_SERVER_UTM_SOURCE);
  url.searchParams.set("utm_medium", surface);
  url.searchParams.set("utm_content", CLOUD_UPGRADE_UTM_CONTENT[feature]);

  return url.toString();
};

const isCloudUpgradeTrialIncluded = (feature: CloudUpgradeFeature) =>
  CLOUD_UPGRADE_CONTENT[feature].trialIncluded;

// Paid-plan-only capabilities point to plans so nobody starts a trial to find them locked.
export const getCloudUpgradePrimaryUrl = (
  feature: CloudUpgradeFeature,
  surface: CloudUpgradeSurface = CLOUD_UPGRADE_SURFACE.BADGE,
) =>
  buildCloudUpgradeUrl(
    isCloudUpgradeTrialIncluded(feature) ? CLOUD_SIGN_UP_URL : PRICING_URL,
    feature,
    surface,
  );

export const getCloudUpgradeCompareUrl = (
  feature: CloudUpgradeFeature,
  surface: CloudUpgradeSurface = CLOUD_UPGRADE_SURFACE.BADGE,
) => buildCloudUpgradeUrl(PRICING_URL, feature, surface);

export const getPrivateCloudContactUrl = (
  feature: CloudUpgradeFeature,
  surface: CloudUpgradeSurface = CLOUD_UPGRADE_SURFACE.BADGE,
) => buildCloudUpgradeUrl(PRIVATE_CLOUD_CONTACT_URL, feature, surface);

export const getCloudUpgradePrimaryCta = (feature: CloudUpgradeFeature) =>
  isCloudUpgradeTrialIncluded(feature)
    ? { label: CLOUD_UPGRADE_TRIAL_CTA, note: CLOUD_UPGRADE_TRIAL_NOTE }
    : { label: CLOUD_UPGRADE_PLANS_CTA, note: CLOUD_UPGRADE_PLANS_NOTE };

export const isCloudUpgradeFeature = (
  feature: UpgradeFeature,
): feature is CloudUpgradeFeature => feature in CLOUD_UPGRADE_CONTENT;

export const PAID_PLAN_UPGRADE_BADGE = "Available on paid plans";
export const PAID_PLAN_UPGRADE_ADMIN_NOTE =
  "Ask an account admin to upgrade your plan.";

const CLOUD_UTM_SOURCE = "prowler-cloud";

const PAID_PLAN_UPGRADE_UTM_CONTENT = {
  [PAID_PLAN_UPGRADE_FEATURE.AI_SECURITY]: "ai-security",
  [PAID_PLAN_UPGRADE_FEATURE.FINDINGS_PREVIEW]: "findings-preview",
  [PAID_PLAN_UPGRADE_FEATURE.REGISTRY]: "registry",
  [PAID_PLAN_UPGRADE_FEATURE.REPORT_DOWNLOAD]: "report-download",
  [PAID_PLAN_UPGRADE_FEATURE.S3_INTEGRATION]: "s3-integration",
} as const satisfies Record<PaidPlanUpgradeFeature, string>;

export const PAID_PLAN_UPGRADE_CONTENT = {
  [PAID_PLAN_UPGRADE_FEATURE.AI_SECURITY]: {
    title: "Unlock AI Security",
    description: "AI Security is included in paid plans.",
    benefits: [
      "Scan Claude, OpenAI and ChatGPT organizations next to your cloud accounts",
      "Score them against OWASP LLM Top 10 and the other AI frameworks",
      "The same checks stay free in the CLI with a Prowler Registry account",
    ],
    primaryCta: "Upgrade to Unlock AI Security",
  },
  [PAID_PLAN_UPGRADE_FEATURE.FINDINGS_PREVIEW]: {
    title: "See Every Finding in Your Account",
    description: `Trial accounts preview the ${FINDINGS_PREVIEW_ROW_LIMIT} most critical finding groups. Paid plans unlock the full list.`,
    benefits: [
      "Browse, sort, and page through every finding group",
      "Drill into each affected resource across all your providers",
      "Download reports and compliance evidence for the full scan",
    ],
    primaryCta: "Upgrade to See All Findings",
  },
  [PAID_PLAN_UPGRADE_FEATURE.REGISTRY]: {
    title: "Unlock Prowler Registry",
    description: "Prowler Registry is included in paid plans.",
    benefits: [
      "Connect custom cloud providers",
      "Extend your assessments with custom security checks",
      "Use private compliance frameworks across your accounts",
    ],
    primaryCta: "Upgrade to Unlock Registry",
  },
  [PAID_PLAN_UPGRADE_FEATURE.REPORT_DOWNLOAD]: {
    title: "Download Your Scan Reports",
    description: "Report downloads are included in Prowler Cloud paid plans.",
    benefits: [
      "Download the full scan output in CSV, JSON-OCSF, and HTML",
      "Export compliance reports as CSV, OCSF, and PDF",
      "Share evidence with auditors and your team",
    ],
    primaryCta: "Upgrade to Download",
  },
  [PAID_PLAN_UPGRADE_FEATURE.S3_INTEGRATION]: {
    title: "Export Findings to Amazon S3",
    description: "Amazon S3 exports are included in Prowler Cloud paid plans.",
    benefits: AMAZON_S3_BENEFITS,
    primaryCta: "Upgrade to Export to S3",
  },
} as const satisfies Record<PaidPlanUpgradeFeature, PaidPlanUpgradeContent>;

export const isPaidPlanUpgradeFeature = (
  feature: UpgradeFeature,
): feature is PaidPlanUpgradeFeature => feature in PAID_PLAN_UPGRADE_CONTENT;

export const getPaidPlanUpgradeBillingHref = (
  feature: PaidPlanUpgradeFeature,
) => `/billing?${new URLSearchParams({ feature })}`;

export const getPaidPlanUpgradeCompareUrl = (
  feature: PaidPlanUpgradeFeature,
) => {
  const url = new URL(PRICING_URL);
  url.searchParams.set("utm_source", CLOUD_UTM_SOURCE);
  url.searchParams.set("utm_content", PAID_PLAN_UPGRADE_UTM_CONTENT[feature]);

  return url.toString();
};
