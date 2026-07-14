import { describe, expect, it } from "vitest";

import {
  CLOUD_UPGRADE_CONTENT,
  CLOUD_UPGRADE_FEATURE,
  CLOUD_UPGRADE_FOOTER_NOTE,
  CLOUD_UPGRADE_SECONDARY_CTA,
  getCloudUpgradeCompareUrl,
  getCloudUpgradePrimaryUrl,
} from "./cloud-upgrade";

describe("CLOUD_UPGRADE_CONTENT", () => {
  it("should expose the approved Alerts upgrade copy", () => {
    // Given / When
    const content = CLOUD_UPGRADE_CONTENT[CLOUD_UPGRADE_FEATURE.ALERTS];

    // Then
    expect(content).toEqual({
      title: "Turn findings into alerts",
      description:
        "Get notified when the findings you care about appear in a scan.",
      benefits: [
        "Get alerted on what matters most",
        "Notify the right people after every scan",
        "Manage alert rules from one place",
      ],
      primaryCta: "Create alerts in Prowler Cloud",
    });
  });

  it("should expose approved copy for every contextual upgrade", () => {
    // Given / When
    const content = CLOUD_UPGRADE_CONTENT;

    // Then
    expect(content).toEqual({
      advanced_scheduling: {
        title: "Keep every provider checked automatically",
        description:
          "Run scans on the cadence you choose without maintaining scheduling infrastructure.",
        benefits: [
          "Choose daily, interval, weekly, or monthly scans",
          "Set scan times in your preferred timezone",
          "Manage schedules alongside scan history",
        ],
        primaryCta: "Schedule scans in Prowler Cloud",
      },
      alerts: {
        title: "Turn findings into alerts",
        description:
          "Get notified when the findings you care about appear in a scan.",
        benefits: [
          "Get alerted on what matters most",
          "Notify the right people after every scan",
          "Manage alert rules from one place",
        ],
        primaryCta: "Create alerts in Prowler Cloud",
      },
      aws_organizations: {
        title: "Add your entire AWS Organization",
        description:
          "Discover accounts and organizational units, then manage them from one place.",
        benefits: [
          "Discover accounts and organizational units automatically",
          "Choose exactly which accounts to onboard",
          "Apply schedules across the selected accounts",
        ],
        primaryCta: "Set up AWS Organizations in Prowler Cloud",
      },
      cli_import: {
        title: "Bring CLI findings into one Cloud view",
        description:
          "Send Prowler CLI scan results to Prowler Cloud for centralized analysis and collaboration.",
        benefits: [
          "Push results directly with --push-to-cloud",
          "Track CLI and managed scans in one place",
          "Automate findings ingestion from CI/CD pipelines",
        ],
        primaryCta: "Import CLI findings in Prowler Cloud",
      },
      cross_provider_compliance: {
        title: "See compliance across every provider",
        description:
          "Replace separate scan reports with a consolidated compliance view.",
        benefits: [
          "Compare framework posture across providers",
          "Find coverage gaps without switching scans",
          "Generate a consolidated compliance report",
        ],
        primaryCta: "Consolidate compliance in Prowler Cloud",
      },
      finding_triage: {
        title: "Coordinate finding remediation",
        description:
          "Add investigation notes and move findings through a shared remediation workflow.",
        benefits: [
          "Preserve investigation context on each finding",
          "Track review and remediation status",
          "Keep triage history with future scans",
        ],
        primaryCta: "Triage findings in Prowler Cloud",
      },
      lighthouse_ai: {
        title: "Use a managed security assistant",
        description:
          "Investigate and act on your security posture without operating an AI stack.",
        benefits: [
          "Start without provisioning or managing OpenAI API keys",
          "Automate security workflows through the hosted remote MCP server",
          "Keep Lighthouse actions grounded in your Prowler Cloud data",
        ],
        primaryCta: "Open Lighthouse in Prowler Cloud",
      },
      general: {
        title: "Scale Prowler without operating it",
        description:
          "Add managed automation and collaboration while Prowler operates the platform.",
        benefits: [
          "Onboard AWS Organizations from the UI",
          "Automate scans, alerts, and compliance reporting",
          "Use managed infrastructure, support, and backups",
        ],
        primaryCta: "Start a Prowler Cloud trial",
      },
      scan_configuration: {
        title: "Configure every scan once",
        description:
          "Create reusable scan configurations instead of rebuilding options for each run.",
        benefits: [
          "Reduce noise by fine-tuning scan configurations",
          "Apply consistent configurations to providers",
          "Manage scan behavior from one place",
        ],
        primaryCta: "Configure scans in Prowler Cloud",
      },
    });
    expect(Object.values(CLOUD_UPGRADE_FEATURE)).toHaveLength(9);
    expect(CLOUD_UPGRADE_SECONDARY_CTA).toBe("Compare editions");
    expect(CLOUD_UPGRADE_FOOTER_NOTE).toBe(
      "Prowler Cloud opens in a new tab. Your self-hosted deployment remains unchanged.",
    );
  });
});

describe("cloud upgrade URLs", () => {
  it("should attribute the primary Cloud destination", () => {
    // Given / When
    const url = getCloudUpgradePrimaryUrl(CLOUD_UPGRADE_FEATURE.ALERTS);

    // Then
    expect(url).toBe(
      "https://cloud.prowler.com/?source=prowler_local_server&feature=alerts",
    );
  });

  it("should attribute the compare editions destination", () => {
    // Given / When
    const url = getCloudUpgradeCompareUrl(
      CLOUD_UPGRADE_FEATURE.CROSS_PROVIDER_COMPLIANCE,
    );

    // Then
    expect(url).toBe(
      "https://prowler.com/pricing?source=prowler_local_server&feature=cross_provider_compliance",
    );
  });
});
