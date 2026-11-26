import { beforeEach, describe, expect, it } from "vitest";

import {
  CLOUD_UPGRADE_FEATURE,
  CLOUD_UPGRADE_SURFACE,
} from "@/types/cloud-upgrade";

import { useCloudUpgradeStore } from "./store";

describe("useCloudUpgradeStore", () => {
  beforeEach(() => {
    useCloudUpgradeStore.setState({
      activeFeature: null,
      retainedFeature: CLOUD_UPGRADE_FEATURE.GENERAL,
      surface: CLOUD_UPGRADE_SURFACE.BADGE,
      returnFocusElement: null,
    });
  });

  it("records the surface that opened the upgrade", () => {
    // Given / When
    useCloudUpgradeStore
      .getState()
      .openCloudUpgrade(
        CLOUD_UPGRADE_FEATURE.REALTIME,
        undefined,
        CLOUD_UPGRADE_SURFACE.SIDEBAR,
      );

    // Then
    expect(useCloudUpgradeStore.getState().surface).toBe(
      CLOUD_UPGRADE_SURFACE.SIDEBAR,
    );
  });

  it("resets the surface to the badge when none is given", () => {
    // Given
    useCloudUpgradeStore
      .getState()
      .openCloudUpgrade(
        CLOUD_UPGRADE_FEATURE.REALTIME,
        undefined,
        CLOUD_UPGRADE_SURFACE.SIDEBAR,
      );

    // When
    useCloudUpgradeStore
      .getState()
      .openCloudUpgrade(CLOUD_UPGRADE_FEATURE.ALERTS);

    // Then
    expect(useCloudUpgradeStore.getState().surface).toBe(
      CLOUD_UPGRADE_SURFACE.BADGE,
    );
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
