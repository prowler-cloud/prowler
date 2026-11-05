import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, beforeEach, describe, expect, it } from "vitest";

import {
  PROVIDER_FUNNEL_EVENT,
  type ProviderFunnelDetail,
} from "@/lib/provider-funnel/provider-funnel-events";

import { CredentialsRoleHelper } from "./credentials-role-helper";

const templateLinks = {
  cloudformation: "https://example.com/template.yml",
  cloudformationQuickLink: "https://example.com/quick-create",
  terraform: "https://example.com/terraform",
};

describe("CredentialsRoleHelper", () => {
  const funnelSignals: ProviderFunnelDetail[] = [];
  const recordFunnelSignal: EventListener = (event) => {
    funnelSignals.push((event as CustomEvent<ProviderFunnelDetail>).detail);
  };

  beforeEach(() => {
    funnelSignals.length = 0;
    window.addEventListener(PROVIDER_FUNNEL_EVENT, recordFunnelSignal);
  });

  afterEach(() => {
    window.removeEventListener(PROVIDER_FUNNEL_EVENT, recordFunnelSignal);
  });

  describe("when connecting a provider", () => {
    it("signals which role template the user opened", async () => {
      // Given
      const user = userEvent.setup();
      render(
        <CredentialsRoleHelper
          externalId="tenant-1"
          templateLinks={templateLinks}
        />,
      );

      // When
      await user.click(
        screen.getByRole("link", { name: /Create the IAM role in AWS/i }),
      );
      await user.click(
        screen.getByRole("button", { name: /Other ways to create the role/i }),
      );
      await user.click(
        screen.getByRole("link", { name: "CloudFormation Template" }),
      );
      await user.click(screen.getByRole("link", { name: "Terraform Code" }));

      // Then
      expect(funnelSignals).toEqual([
        {
          step: "role_template_opened",
          template: "cloudformation_quick_create",
        },
        { step: "role_template_opened", template: "cloudformation_template" },
        { step: "role_template_opened", template: "terraform" },
      ]);
    });
  });

  describe("when configuring an integration", () => {
    it("stays out of the provider funnel", async () => {
      // Given
      const user = userEvent.setup();
      render(
        <CredentialsRoleHelper
          externalId="tenant-1"
          templateLinks={templateLinks}
          integrationType="amazon_s3"
        />,
      );

      // When
      await user.click(
        screen.getByRole("link", { name: /Create the IAM role in AWS/i }),
      );

      // Then
      expect(funnelSignals).toEqual([]);
    });
  });
});
