import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, describe, expect, it, vi } from "vitest";

import { useCloudUpgradeStore } from "@/store";
import { CLOUD_UPGRADE_FEATURE } from "@/types/cloud-upgrade";

import { AwsMethodSelector } from "./aws-method-selector";

describe("AwsMethodSelector", () => {
  afterEach(() => {
    vi.unstubAllEnvs();
    useCloudUpgradeStore.getState().closeCloudUpgrade();
  });

  it("opens the AWS Organizations upgrade in Local Server", async () => {
    // Given
    vi.stubEnv("UI_CLOUD_ENABLED", "false");
    const user = userEvent.setup();
    const onSelectOrganizations = vi.fn();

    // When
    render(
      <AwsMethodSelector
        onSelectSingle={vi.fn()}
        onSelectOrganizations={onSelectOrganizations}
      />,
    );

    // Then
    await user.click(
      screen.getByRole("radio", {
        name: /add multiple accounts with aws organizations/i,
      }),
    );

    expect(onSelectOrganizations).not.toHaveBeenCalled();
    expect(screen.getByText("Cloud")).toBeVisible();
    expect(useCloudUpgradeStore.getState().activeFeature).toBe(
      CLOUD_UPGRADE_FEATURE.AWS_ORGANIZATIONS,
    );
  });
});
