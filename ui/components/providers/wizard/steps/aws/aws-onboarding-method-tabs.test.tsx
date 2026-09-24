import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, describe, expect, it, vi } from "vitest";

import { useCloudUpgradeStore } from "@/store";
import { CLOUD_UPGRADE_FEATURE } from "@/types/cloud-upgrade";

import {
  AWS_ONBOARDING_METHOD,
  AwsOnboardingMethodTabs,
} from "./aws-onboarding-method-tabs";

describe("AwsOnboardingMethodTabs", () => {
  afterEach(() => {
    vi.unstubAllEnvs();
    useCloudUpgradeStore.getState().closeCloudUpgrade();
  });

  it("switches to the organization flow in Cloud", async () => {
    vi.stubEnv("UI_CLOUD_ENABLED", "true");
    const user = userEvent.setup();
    const onSelectOrganizations = vi.fn();
    render(
      <AwsOnboardingMethodTabs
        value={AWS_ONBOARDING_METHOD.SINGLE}
        onSelectSingle={vi.fn()}
        onSelectOrganizations={onSelectOrganizations}
      />,
    );

    await user.click(
      screen.getByRole("tab", { name: /Full AWS Organization/ }),
    );

    expect(onSelectOrganizations).toHaveBeenCalledOnce();
    expect(screen.queryByText("Cloud")).not.toBeInTheDocument();
  });

  it("opens the AWS Organizations upgrade in Local Server", async () => {
    vi.stubEnv("UI_CLOUD_ENABLED", "false");
    const user = userEvent.setup();
    const onSelectOrganizations = vi.fn();
    render(
      <AwsOnboardingMethodTabs
        value={AWS_ONBOARDING_METHOD.SINGLE}
        onSelectSingle={vi.fn()}
        onSelectOrganizations={onSelectOrganizations}
      />,
    );

    await user.click(
      screen.getByRole("tab", { name: /Full AWS Organization/ }),
    );

    expect(onSelectOrganizations).not.toHaveBeenCalled();
    expect(screen.getByText("Cloud")).toBeVisible();
    expect(useCloudUpgradeStore.getState().activeFeature).toBe(
      CLOUD_UPGRADE_FEATURE.AWS_ORGANIZATIONS,
    );
  });

  it("returns to the single account flow from the organization tab", async () => {
    const user = userEvent.setup();
    const onSelectSingle = vi.fn();
    render(
      <AwsOnboardingMethodTabs
        value={AWS_ONBOARDING_METHOD.ORGANIZATION}
        onSelectSingle={onSelectSingle}
        onSelectOrganizations={vi.fn()}
      />,
    );

    await user.click(screen.getByRole("tab", { name: "Single AWS Account" }));

    expect(onSelectSingle).toHaveBeenCalledOnce();
  });
});
