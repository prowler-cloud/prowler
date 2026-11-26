import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, describe, expect, it } from "vitest";

import { TooltipProvider } from "@/components/shadcn/tooltip";
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
    render(
      <TooltipProvider>
        <ManagedLighthouseCallout />
      </TooltipProvider>,
    );

    const upgradeButton = screen.getByRole("button", {
      name: "See Managed Lighthouse AI",
    });

    // When
    await user.click(upgradeButton);

    // Then
    expect(upgradeButton).toHaveClass("bg-button-primary");
    expect(useCloudUpgradeStore.getState().activeFeature).toBe(
      CLOUD_UPGRADE_FEATURE.LIGHTHOUSE_AI,
    );
  });

  it("compares bring-your-own-key and managed Lighthouse without naming one vendor", () => {
    // Given / When
    render(
      <TooltipProvider>
        <ManagedLighthouseCallout />
      </TooltipProvider>,
    );

    // Then
    expect(screen.getByText("Your Lighthouse AI")).toBeVisible();
    expect(screen.getAllByText("Managed Lighthouse AI").length).toBeGreaterThan(
      0,
    );
    expect(screen.queryByText(/OpenAI/)).not.toBeInTheDocument();
  });
});
