import { afterEach, describe, expect, it } from "vitest";

import { CLOUD_UPGRADE_FEATURE } from "@/lib/cloud-upgrade";

import { useCloudUpgradeStore } from "./store";

describe("useCloudUpgradeStore", () => {
  afterEach(() => {
    useCloudUpgradeStore.getState().closeCloudUpgrade();
  });

  it("opens one contextual upgrade at a time", () => {
    // Given / When
    useCloudUpgradeStore
      .getState()
      .openCloudUpgrade(CLOUD_UPGRADE_FEATURE.ALERTS);
    useCloudUpgradeStore
      .getState()
      .openCloudUpgrade(CLOUD_UPGRADE_FEATURE.FINDING_TRIAGE);

    // Then
    expect(useCloudUpgradeStore.getState().activeFeature).toBe(
      CLOUD_UPGRADE_FEATURE.FINDING_TRIAGE,
    );
  });

  it("closes the active contextual upgrade", () => {
    // Given
    useCloudUpgradeStore
      .getState()
      .openCloudUpgrade(CLOUD_UPGRADE_FEATURE.GENERAL);

    // When
    useCloudUpgradeStore.getState().closeCloudUpgrade();

    // Then
    expect(useCloudUpgradeStore.getState().activeFeature).toBeNull();
  });
});
