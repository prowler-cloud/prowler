import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, describe, expect, it } from "vitest";

import { useCloudUpgradeStore } from "@/store";
import { CLOUD_UPGRADE_FEATURE } from "@/types/cloud-upgrade";

import { ManagedLighthouseCallout } from "./managed-lighthouse-callout";

describe("ManagedLighthouseCallout", () => {
  afterEach(() => {
    useCloudUpgradeStore.getState().closeCloudUpgrade();
  });

  it("opens the managed Lighthouse Cloud upgrade", async () => {
    // Given
    const user = userEvent.setup();
    render(<ManagedLighthouseCallout />);

    const upgradeButton = screen.getByRole("button", {
      name: "Explore The Agentic Cloud Defender",
    });

    // When
    await user.click(upgradeButton);

    // Then
    expect(upgradeButton).toHaveClass("bg-button-primary");
    expect(useCloudUpgradeStore.getState().activeFeature).toBe(
      CLOUD_UPGRADE_FEATURE.LIGHTHOUSE_AI,
    );
  });
});
