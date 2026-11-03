import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, describe, expect, it, vi } from "vitest";

import { useCloudUpgradeStore } from "@/store";
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

  it("hides organization onboarding self-hosted until its backend ships (no upsell)", () => {
    vi.stubEnv("UI_CLOUD_ENABLED", "false");
    const { container } = render(
      <OnboardingMethodTabs
        orgType={ORGANIZATION_TYPE.AWS}
        value={ONBOARDING_METHOD.SINGLE}
        onSelectSingle={vi.fn()}
        onSelectOrganizations={vi.fn()}
      />,
    );

    expect(container).toBeEmptyDOMElement();
    expect(useCloudUpgradeStore.getState().activeFeature).toBeNull();
  });

  it("offers organization onboarding once switched on per deployment", async () => {
    vi.stubEnv("UI_CLOUD_ENABLED", "false");
    vi.stubEnv("NEXT_PUBLIC_CLOUDY_FEATURES", "aws_organizations");
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
  });

  it("returns to the single account flow from the organization tab", async () => {
    vi.stubEnv("UI_CLOUD_ENABLED", "true");
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
    { orgType: ORGANIZATION_TYPE.AZURE },
    { orgType: ORGANIZATION_TYPE.GCP },
  ])(
    "hides the $orgType organization flow self-hosted instead of upselling it",
    ({ orgType }) => {
      vi.stubEnv("UI_CLOUD_ENABLED", "false");
      const { container } = render(
        <OnboardingMethodTabs
          orgType={orgType}
          value={ONBOARDING_METHOD.SINGLE}
          onSelectSingle={vi.fn()}
          onSelectOrganizations={vi.fn()}
        />,
      );

      expect(container).toBeEmptyDOMElement();
      expect(useCloudUpgradeStore.getState().activeFeature).toBeNull();
    },
  );
});
