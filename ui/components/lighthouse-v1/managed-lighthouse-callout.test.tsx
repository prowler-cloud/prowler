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

    // When
    await user.click(
      screen.getByRole("button", {
        name: "Explore the fully Managed Lighthouse AI",
      }),
    );

    // Then
    expect(useCloudUpgradeStore.getState().activeFeature).toBe(
      CLOUD_UPGRADE_FEATURE.LIGHTHOUSE_AI,
    );
  });
});
