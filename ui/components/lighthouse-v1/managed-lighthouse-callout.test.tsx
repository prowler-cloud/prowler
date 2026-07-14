import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, describe, expect, it } from "vitest";

import { CLOUD_UPGRADE_FEATURE } from "@/lib/cloud-upgrade";
import { useCloudUpgradeStore } from "@/store";

import { ManagedLighthouseCallout } from "./managed-lighthouse-callout";

describe("ManagedLighthouseCallout", () => {
  afterEach(() => {
    useCloudUpgradeStore.getState().closeCloudUpgrade();
  });

  it("opens the managed Lighthouse Cloud upgrade", async () => {
    // Given
    const user = userEvent.setup();
    render(<ManagedLighthouseCallout />);

    // When
    await user.click(
      screen.getByRole("button", {
        name: "Explore the fully Managed Lighthouse AI",
      }),
    );

    // Then
    expect(screen.getByText("Skip the setup with Prowler Cloud")).toBeVisible();
    expect(
      screen.getByText(/managed OpenAI access with no API keys to provision/i),
    ).toBeVisible();
    expect(useCloudUpgradeStore.getState().activeFeature).toBe(
      CLOUD_UPGRADE_FEATURE.LIGHTHOUSE_AI,
    );
  });
});
