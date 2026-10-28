import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, describe, expect, it, vi } from "vitest";

import { useCloudUpgradeStore } from "@/store";
import { CLOUD_UPGRADE_FEATURE } from "@/types/cloud-upgrade";
import { ORGANIZATION_TYPE } from "@/types/organizations";

import {
  ONBOARDING_METHOD,
  OnboardingMethodTabs,
} from "./onboarding-method-tabs";

describe("OnboardingMethodTabs", () => {
  afterEach(() => {
    vi.unstubAllEnvs();
    useCloudUpgradeStore.getState().closeCloudUpgrade();
  });

  it("switches to the organization flow in Cloud", async () => {
    vi.stubEnv("UI_CLOUD_ENABLED", "true");
    const user = userEvent.setup();
    const onSelectOrganizations = vi.fn();
    render(
      <OnboardingMethodTabs
        orgType={ORGANIZATION_TYPE.AWS}
        value={ONBOARDING_METHOD.SINGLE}
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
      <OnboardingMethodTabs
        orgType={ORGANIZATION_TYPE.AWS}
        value={ONBOARDING_METHOD.SINGLE}
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
      <OnboardingMethodTabs
        orgType={ORGANIZATION_TYPE.AWS}
        value={ONBOARDING_METHOD.ORGANIZATION}
        onSelectSingle={onSelectSingle}
        onSelectOrganizations={vi.fn()}
      />,
    );

    await user.click(screen.getByRole("tab", { name: "Single AWS Account" }));

    expect(onSelectSingle).toHaveBeenCalledOnce();
  });

  it.each([
    {
      orgType: ORGANIZATION_TYPE.AZURE,
      tab: "Azure Management Group",
      feature: CLOUD_UPGRADE_FEATURE.AZURE_ORGANIZATIONS,
    },
    {
      orgType: ORGANIZATION_TYPE.GCP,
      tab: "Full GCP Organization",
      feature: CLOUD_UPGRADE_FEATURE.GCP_ORGANIZATIONS,
    },
  ])(
    "offers the $orgType organization flow behind its own upgrade outside Cloud",
    async ({ orgType, tab, feature }) => {
      vi.stubEnv("UI_CLOUD_ENABLED", "false");
      const user = userEvent.setup();
      const onSelectOrganizations = vi.fn();
      render(
        <OnboardingMethodTabs
          orgType={orgType}
          value={ONBOARDING_METHOD.SINGLE}
          onSelectOrganizations={onSelectOrganizations}
        />,
      );

      await user.click(screen.getByRole("tab", { name: new RegExp(tab) }));

      expect(onSelectOrganizations).not.toHaveBeenCalled();
      expect(useCloudUpgradeStore.getState().activeFeature).toBe(feature);
    },
  );
});
