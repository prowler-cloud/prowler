import { cleanup, render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, describe, expect, it, vi } from "vitest";

import { CLOUD_UPGRADE_FEATURE } from "@/lib/cloud-upgrade";
import { useCloudUpgradeStore } from "@/store/cloud-upgrade/store";

import { CloudUpgradeModal } from "./cloud-upgrade-modal";

describe("CloudUpgradeModal", () => {
  afterEach(() => {
    cleanup();
    vi.unstubAllEnvs();
    useCloudUpgradeStore.getState().closeCloudUpgrade();
  });

  it("renders the active contextual upgrade in Local Server", async () => {
    // Given
    vi.stubEnv("NEXT_PUBLIC_IS_CLOUD_ENV", "false");
    useCloudUpgradeStore
      .getState()
      .openCloudUpgrade(CLOUD_UPGRADE_FEATURE.ALERTS);

    // When
    render(<CloudUpgradeModal />);

    // Then
    expect(
      await screen.findByRole("dialog", { name: "Turn findings into alerts" }),
    ).toBeVisible();
    expect(screen.getByText("Available in Prowler Cloud")).toBeVisible();
    expect(
      screen.getByRole("link", { name: "Create Alerts in Prowler Cloud" }),
    ).toHaveAttribute(
      "href",
      "https://cloud.prowler.com/sign-up?source=prowler_local_server&feature=alerts",
    );
    expect(
      screen.getByRole("link", { name: "View Plans & Pricing" }),
    ).toHaveAttribute(
      "href",
      "https://prowler.com/pricing?source=prowler_local_server&feature=alerts",
    );
  });

  it("uses a wider responsive dialog for long contextual CTAs", async () => {
    // Given
    vi.stubEnv("NEXT_PUBLIC_IS_CLOUD_ENV", "false");
    useCloudUpgradeStore
      .getState()
      .openCloudUpgrade(CLOUD_UPGRADE_FEATURE.AWS_ORGANIZATIONS);

    // When
    render(<CloudUpgradeModal />);

    const dialog = await screen.findByRole("dialog", {
      name: "Add your entire AWS Organization",
    });

    // Then
    expect(dialog).toHaveClass("max-w-[calc(100%-2rem)]", "sm:max-w-xl");
    expect(dialog).not.toHaveClass("sm:max-w-lg");
    const primaryCta = screen.getByRole("link", {
      name: "Set Up AWS Organizations in Prowler Cloud",
    });
    const secondaryCta = screen.getByRole("link", {
      name: "View Plans & Pricing",
    });
    const ctaGroup = primaryCta.parentElement;

    const primaryLabel = screen.getByText(
      "Set Up AWS Organizations in Prowler Cloud",
    );
    const secondaryLabel = screen.getByText("View Plans & Pricing");

    expect(ctaGroup).toHaveClass("flex-col", "sm:flex-row");
    expect(primaryCta).toHaveClass("w-full", "min-w-0", "shrink", "sm:flex-1");
    expect(secondaryCta).toHaveClass(
      "w-full",
      "min-w-0",
      "shrink",
      "sm:flex-1",
    );
    expect(primaryLabel).toHaveClass("max-w-full", "truncate");
    expect(secondaryLabel).toHaveClass("max-w-full", "truncate");
    expect(primaryCta).toHaveAttribute(
      "title",
      "Set Up AWS Organizations in Prowler Cloud",
    );
  });

  it("closes the active upgrade and returns focus to its trigger", async () => {
    // Given
    vi.stubEnv("NEXT_PUBLIC_IS_CLOUD_ENV", "false");
    const user = userEvent.setup();

    render(
      <>
        <button
          type="button"
          onClick={() =>
            useCloudUpgradeStore
              .getState()
              .openCloudUpgrade(CLOUD_UPGRADE_FEATURE.GENERAL)
          }
        >
          Explore Prowler Cloud
        </button>
        <CloudUpgradeModal />
      </>,
    );

    const trigger = screen.getByRole("button", {
      name: "Explore Prowler Cloud",
    });
    await user.click(trigger);

    // When
    await user.click(screen.getByRole("button", { name: "Close" }));

    // Then
    expect(screen.queryByRole("dialog")).not.toBeInTheDocument();
    expect(trigger).toHaveFocus();
    expect(useCloudUpgradeStore.getState().activeFeature).toBeNull();
  });

  it("does not render upgrade UI in Prowler Cloud", () => {
    // Given
    vi.stubEnv("NEXT_PUBLIC_IS_CLOUD_ENV", "true");
    useCloudUpgradeStore
      .getState()
      .openCloudUpgrade(CLOUD_UPGRADE_FEATURE.ALERTS);

    // When
    render(<CloudUpgradeModal />);

    // Then
    expect(screen.queryByRole("dialog")).not.toBeInTheDocument();
  });
});
