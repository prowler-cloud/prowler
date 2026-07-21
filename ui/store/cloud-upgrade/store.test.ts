import { beforeEach, describe, expect, it } from "vitest";

import { CLOUD_UPGRADE_FEATURE } from "@/types/cloud-upgrade";

import { useCloudUpgradeStore } from "./store";

describe("useCloudUpgradeStore", () => {
  beforeEach(() => {
    useCloudUpgradeStore.setState({
      activeFeature: null,
      retainedFeature: CLOUD_UPGRADE_FEATURE.GENERAL,
      returnFocusElement: null,
    });
  });

  it("retains the opened feature when the modal closes", () => {
    // Given
    useCloudUpgradeStore
      .getState()
      .openCloudUpgrade(CLOUD_UPGRADE_FEATURE.ALERTS);

    // When
    useCloudUpgradeStore.getState().closeCloudUpgrade();

    // Then
    expect(useCloudUpgradeStore.getState().activeFeature).toBeNull();
    expect(useCloudUpgradeStore.getState().retainedFeature).toBe(
      CLOUD_UPGRADE_FEATURE.ALERTS,
    );
  });

  it("updates the retained feature when another upgrade opens", () => {
    // Given
    useCloudUpgradeStore
      .getState()
      .openCloudUpgrade(CLOUD_UPGRADE_FEATURE.ALERTS);

    // When
    useCloudUpgradeStore
      .getState()
      .openCloudUpgrade(CLOUD_UPGRADE_FEATURE.AWS_ORGANIZATIONS);

    // Then
    expect(useCloudUpgradeStore.getState().activeFeature).toBe(
      CLOUD_UPGRADE_FEATURE.AWS_ORGANIZATIONS,
    );
    expect(useCloudUpgradeStore.getState().retainedFeature).toBe(
      CLOUD_UPGRADE_FEATURE.AWS_ORGANIZATIONS,
    );
  });
});
