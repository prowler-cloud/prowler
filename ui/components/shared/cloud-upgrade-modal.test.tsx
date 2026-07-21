import { cleanup, render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, describe, expect, it, vi } from "vitest";

import { useCloudUpgradeStore } from "@/store/cloud-upgrade/store";
import { CLOUD_UPGRADE_FEATURE } from "@/types/cloud-upgrade";

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
      await screen.findByRole("dialog", { name: "Turn Findings into Alerts" }),
    ).toBeVisible();
    expect(screen.getByText("Available in Prowler Cloud")).toBeVisible();
    expect(
      screen.getByRole("link", { name: "Create Alerts in Prowler Cloud" }),
    ).toHaveAttribute(
      "href",
      "https://cloud.prowler.com/sign-up?utm_source=prowler-local-server&utm_content=alerts",
    );
    expect(
      screen.getByRole("link", { name: "View Plans & Pricing" }),
    ).toHaveAttribute(
      "href",
      "https://prowler.com/pricing?utm_source=prowler-local-server&utm_content=alerts",
    );
  });

  it("uses the standard equal-width CTA layout", async () => {
    // Given
    vi.stubEnv("NEXT_PUBLIC_IS_CLOUD_ENV", "false");
    useCloudUpgradeStore
      .getState()
      .openCloudUpgrade(CLOUD_UPGRADE_FEATURE.AWS_ORGANIZATIONS);

    // When
    render(<CloudUpgradeModal />);

    // Then
    const dialog = await screen.findByRole("dialog", {
      name: "Add Your Entire AWS Organization",
    });
    const primaryCta = screen.getByRole("link", {
      name: "Set Up AWS Organizations in Prowler Cloud",
    });
    const secondaryCta = screen.getByRole("link", {
      name: "View Plans & Pricing",
    });

    expect(dialog).toHaveClass("sm:max-w-2xl");
    expect(primaryCta.parentElement).toHaveClass("gap-3", "md:flex-row");
    expect(primaryCta).toHaveClass(
      "h-auto",
      "min-h-9",
      "whitespace-normal",
      "md:flex-1",
    );
    expect(secondaryCta).toHaveClass(
      "h-auto",
      "min-h-9",
      "whitespace-normal",
      "md:flex-1",
    );
    expect(primaryCta.querySelector(".truncate")).not.toBeInTheDocument();
    expect(primaryCta).toHaveAttribute(
      "href",
      "https://cloud.prowler.com/sign-up?utm_source=prowler-local-server&utm_content=organization",
    );
  });

  it("renders the contextual Jira dispatch upgrade", async () => {
    // Given
    vi.stubEnv("NEXT_PUBLIC_IS_CLOUD_ENV", "false");
    useCloudUpgradeStore
      .getState()
      .openCloudUpgrade(CLOUD_UPGRADE_FEATURE.JIRA_DISPATCH);

    // When
    render(<CloudUpgradeModal />);

    // Then
    expect(
      await screen.findByRole("dialog", {
        name: "Send Findings to Jira at Scale",
      }),
    ).toBeVisible();
    expect(
      screen.getByRole("link", {
        name: "Send Findings to Jira in Prowler Cloud",
      }),
    ).toHaveAttribute(
      "href",
      "https://cloud.prowler.com/sign-up?utm_source=prowler-local-server&utm_content=jira-dispatch",
    );
    expect(
      screen.getByRole("link", { name: "View Plans & Pricing" }),
    ).toHaveAttribute(
      "href",
      "https://prowler.com/pricing?utm_source=prowler-local-server&utm_content=jira-dispatch",
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
