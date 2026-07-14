import { describe, expect, it } from "vitest";

import { CLOUD_UPGRADE_FEATURE } from "@/types/cloud-upgrade";

import {
  getCloudUpgradeCompareUrl,
  getCloudUpgradePrimaryUrl,
} from "./cloud-upgrade";

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
