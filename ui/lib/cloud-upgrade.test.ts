import { describe, expect, it } from "vitest";

import {
  CLOUD_UPGRADE_FEATURE,
  PAID_PLAN_UPGRADE_FEATURE,
} from "@/types/cloud-upgrade";

import {
  CLOUD_UPGRADE_CONTENT,
  CLOUD_UPGRADE_FOOTER_NOTE,
  getCloudUpgradeCompareUrl,
  getCloudUpgradePrimaryUrl,
  getPaidPlanUpgradeBillingHref,
  getPaidPlanUpgradeCompareUrl,
  isCloudUpgradeFeature,
  isPaidPlanUpgradeFeature,
  PAID_PLAN_UPGRADE_CONTENT,
} from "./cloud-upgrade";

describe("cloud upgrade content", () => {
  it("should use title case for every Cloud modal title", () => {
    // Given / When
    const titles = Object.values(CLOUD_UPGRADE_CONTENT).map(
      (content) => content.title,
    );

    // Then
    expect(titles).toEqual([
      "Keep Every Provider Checked Automatically",
      "Turn Findings into Alerts",
      "Export Findings to Amazon S3",
      "Automate Prowler with API Keys",
      "Add Your Entire AWS Organization",
      "Add Your Entire Azure Management Group",
      "Add Your Entire GCP Organization",
      "Bring CLI Findings into One Cloud View",
      "See Compliance Across Every Provider",
      "Coordinate Finding Remediation",
      "Send Findings to Jira at Scale",
      "Use The Agent Cloud Defender",
      "Scale Prowler Without Operating It",
      "Catch Risky AWS Changes as They Happen",
      "Configure Every Scan Once",
      "Use One SAML Configuration Across Domains",
    ]);
  });

  it("should explain that Prowler Local Server remains unchanged", () => {
    // Given / When / Then
    expect(CLOUD_UPGRADE_FOOTER_NOTE).toBe(
      "Prowler Cloud opens in a new tab. Your Prowler Local Server remains unchanged.",
    );
  });
});

describe("cloud upgrade URLs", () => {
  it("should attribute the primary Cloud destination", () => {
    // Given / When
    const url = getCloudUpgradePrimaryUrl(CLOUD_UPGRADE_FEATURE.ALERTS);

    // Then
    expect(url).toBe(
      "https://cloud.prowler.com/sign-up?utm_source=prowler-local-server&utm_content=alerts",
    );
  });

  it("should attribute the plans and pricing destination", () => {
    // Given / When
    const url = getCloudUpgradeCompareUrl(
      CLOUD_UPGRADE_FEATURE.CROSS_PROVIDER_COMPLIANCE,
    );

    // Then
    expect(url).toBe(
      "https://prowler.com/pricing?utm_source=prowler-local-server&utm_content=cross-provider-compliance",
    );
  });

  it.each([
    [CLOUD_UPGRADE_FEATURE.ADVANCED_SCHEDULING, "advanced-scheduling"],
    [CLOUD_UPGRADE_FEATURE.ALERTS, "alerts"],
    [CLOUD_UPGRADE_FEATURE.AMAZON_S3, "amazon-s3"],
    [CLOUD_UPGRADE_FEATURE.API_KEYS, "api-keys"],
    [CLOUD_UPGRADE_FEATURE.AWS_ORGANIZATIONS, "organization"],
    [CLOUD_UPGRADE_FEATURE.AZURE_ORGANIZATIONS, "azure-organization"],
    [CLOUD_UPGRADE_FEATURE.CLI_IMPORT, "cli-import"],
    [
      CLOUD_UPGRADE_FEATURE.CROSS_PROVIDER_COMPLIANCE,
      "cross-provider-compliance",
    ],
    [CLOUD_UPGRADE_FEATURE.FINDING_TRIAGE, "findings"],
    [CLOUD_UPGRADE_FEATURE.GCP_ORGANIZATIONS, "gcp-organization"],
    [CLOUD_UPGRADE_FEATURE.JIRA_DISPATCH, "jira-dispatch"],
    [CLOUD_UPGRADE_FEATURE.LIGHTHOUSE_AI, "lighthouse-ai"],
    [CLOUD_UPGRADE_FEATURE.GENERAL, "general"],
    [CLOUD_UPGRADE_FEATURE.REALTIME, "realtime"],
    [CLOUD_UPGRADE_FEATURE.SCAN_CONFIGURATION, "scan-configuration"],
    [CLOUD_UPGRADE_FEATURE.SAML_DOMAINS, "saml-domains"],
  ])("should use the canonical content slug for %s", (feature, contentSlug) => {
    // Given / When
    const url = new URL(getCloudUpgradePrimaryUrl(feature));

    // Then
    expect(url.searchParams.get("utm_content")).toBe(contentSlug);
  });
});

describe("paid plan upgrade content", () => {
  it("sends the findings preview upgrade to billing with its feature", () => {
    // Given / When / Then
    expect(
      isPaidPlanUpgradeFeature(PAID_PLAN_UPGRADE_FEATURE.FINDINGS_PREVIEW),
    ).toBe(true);
    expect(
      getPaidPlanUpgradeBillingHref(PAID_PLAN_UPGRADE_FEATURE.FINDINGS_PREVIEW),
    ).toBe("/billing?feature=findings_preview");
    expect(
      PAID_PLAN_UPGRADE_CONTENT[PAID_PLAN_UPGRADE_FEATURE.FINDINGS_PREVIEW]
        .title,
    ).toBe("See Every Finding in Your Account");
  });

  it("sends the Amazon S3 upgrade to billing with its own feature", () => {
    // Given
    const feature = PAID_PLAN_UPGRADE_FEATURE.S3_INTEGRATION;

    // When / Then
    expect(isPaidPlanUpgradeFeature(feature)).toBe(true);
    expect(isCloudUpgradeFeature(feature)).toBe(false);
    expect(getPaidPlanUpgradeBillingHref(feature)).toBe(
      "/billing?feature=s3_integration",
    );
    expect(
      new URL(getPaidPlanUpgradeCompareUrl(feature)).searchParams.get(
        "utm_content",
      ),
    ).toBe("s3-integration");
  });
});
