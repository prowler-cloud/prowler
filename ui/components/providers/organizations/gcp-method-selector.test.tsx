import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, describe, expect, it, vi } from "vitest";

import { useCloudUpgradeStore } from "@/store";
import { CLOUD_UPGRADE_FEATURE } from "@/types/cloud-upgrade";

import { GcpMethodSelector } from "./gcp-method-selector";

// OSS gating only: `CloudUpgradeModal` mounts outside the providers page, so the
// harness cannot see the upsell open. The Cloud case is restated by integration.
describe("GcpMethodSelector", () => {
  afterEach(() => {
    vi.unstubAllEnvs();
    useCloudUpgradeStore.getState().closeCloudUpgrade();
  });

  it("opens the GCP Organizations upgrade in Local Server", async () => {
    // Given
    vi.stubEnv("UI_CLOUD_ENABLED", "false");
    const user = userEvent.setup();
    const onSelectOrganizations = vi.fn();

    // When
    render(
      <GcpMethodSelector
        onSelectSingle={vi.fn()}
        onSelectOrganizations={onSelectOrganizations}
      />,
    );

    // Then
    await user.click(
      screen.getByRole("radio", {
        name: /add multiple projects with gcp organization/i,
      }),
    );

    expect(onSelectOrganizations).not.toHaveBeenCalled();
    expect(screen.getByText("Cloud")).toBeVisible();
    expect(useCloudUpgradeStore.getState().activeFeature).toBe(
      CLOUD_UPGRADE_FEATURE.GCP_ORGANIZATIONS,
    );
  });
});
