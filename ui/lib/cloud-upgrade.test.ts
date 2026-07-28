import { describe, expect, it } from "vitest";

import { CLOUD_UPGRADE_FEATURE } from "@/types/cloud-upgrade";

import {
  CLOUD_UPGRADE_CONTENT,
  CLOUD_UPGRADE_FOOTER_NOTE,
  getCloudUpgradeCompareUrl,
  getCloudUpgradePrimaryUrl,
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
      "Add Your Entire AWS Organization",
      "Bring CLI Findings into One Cloud View",
      "See Compliance Across Every Provider",
      "Coordinate Finding Remediation",
      "Send Findings to Jira at Scale",
      "Use The Agent Cloud Defender",
      "Scale Prowler Without Operating It",
      "Configure Every Scan Once",
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
    [CLOUD_UPGRADE_FEATURE.AWS_ORGANIZATIONS, "organization"],
    [CLOUD_UPGRADE_FEATURE.CLI_IMPORT, "cli-import"],
    [
      CLOUD_UPGRADE_FEATURE.CROSS_PROVIDER_COMPLIANCE,
      "cross-provider-compliance",
    ],
    [CLOUD_UPGRADE_FEATURE.FINDING_TRIAGE, "findings"],
    [CLOUD_UPGRADE_FEATURE.JIRA_DISPATCH, "jira-dispatch"],
    [CLOUD_UPGRADE_FEATURE.LIGHTHOUSE_AI, "lighthouse-ai"],
    [CLOUD_UPGRADE_FEATURE.GENERAL, "general"],
    [CLOUD_UPGRADE_FEATURE.SCAN_CONFIGURATION, "scan-configuration"],
  ])("should use the canonical content slug for %s", (feature, contentSlug) => {
    // Given / When
    const url = new URL(getCloudUpgradePrimaryUrl(feature));

    // Then
    expect(url.searchParams.get("utm_content")).toBe(contentSlug);
  });
});
