import { describe, expect, it } from "vitest";

import { CLOUD_UPGRADE_FEATURE } from "@/types/cloud-upgrade";

import {
  CLOUD_UPGRADE_CONTENT,
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
      "Use a Managed Security Assistant",
      "Scale Prowler Without Operating It",
      "Configure Every Scan Once",
    ]);
  });
});

describe("cloud upgrade URLs", () => {
  it("should attribute the primary Cloud destination", () => {
    // Given / When
    const url = getCloudUpgradePrimaryUrl(CLOUD_UPGRADE_FEATURE.ALERTS);

    // Then
    expect(url).toBe(
      "https://cloud.prowler.com/sign-up?source=prowler_local_server&feature=alerts",
    );
  });

  it("should attribute the plans and pricing destination", () => {
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
