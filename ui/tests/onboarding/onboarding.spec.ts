import { test } from "@playwright/test";

import { deleteProviderIfExists } from "../helpers";
import { ProvidersPage } from "../providers/providers-page";
import { OnboardingPage } from "./onboarding-page";

test.describe("Onboarding", () => {
  // Reuse admin authentication; provider management requires it and the gate
  // reads the already-hydrated `hasProviders` signal from this session.
  test.use({ storageState: "playwright/.auth/admin_user.json" });

  test.describe("Mandatory new-user path", () => {
    // The gate only fires for a zero-provider account, so the existing E2E AWS
    // provider (when configured) is removed and the tour state is cleared.
    const accountId = process.env.E2E_AWS_PROVIDER_ACCOUNT_ID ?? "";

    test.beforeEach(async ({ page }) => {
      const providersPage = new ProvidersPage(page);
      if (accountId) {
        await deleteProviderIfExists(providersPage, accountId);
      }

      // Clear any tour records so the gate evaluates as a fresh browser.
      await providersPage.goto();
      const onboardingPage = new OnboardingPage(page);
      await onboardingPage.clearOnboardingState();
    });

    test(
      "forces the Welcome modal and hands off to the add-provider tour",
      {
        tag: ["@critical", "@e2e", "@onboarding", "@OB-E2E-001"],
      },
      async ({ page }) => {
        test.skip(
          !accountId,
          "E2E_AWS_PROVIDER_ACCOUNT_ID is not set; cannot guarantee a zero-provider account",
        );

        const onboardingPage = new OnboardingPage(page);

        // Reload so the gate re-evaluates with a cleared tour state.
        await onboardingPage.goto("/providers");

        // The zero-provider account is forced into the Welcome modal.
        await onboardingPage.verifyWelcomeModalVisible();

        // Accepting hands off to the providers route (param consumed).
        await onboardingPage.clickGetStarted();
        await onboardingPage.verifyOnProvidersPage();

        // The tour trigger anchor is mounted on the providers surface.
        await onboardingPage.verifyTriggerAnchorPresent();
      },
    );
  });

  test.describe("Restart path", () => {
    test.beforeEach(async ({ page }) => {
      // Land on a page with the user nav, then seed a completed record so the
      // restart entry proves the tour starts despite an existing record.
      const onboardingPage = new OnboardingPage(page);
      await onboardingPage.goto("/providers");
      await onboardingPage.seedCompletedAddProviderRecord();
    });

    test(
      "restarts the tour from the avatar menu despite a completion record",
      {
        tag: ["@high", "@e2e", "@onboarding", "@OB-E2E-002"],
      },
      async ({ page }) => {
        const onboardingPage = new OnboardingPage(page);

        // Reload so the seeded record is in effect for the gate.
        await onboardingPage.goto("/providers");

        // Open the avatar menu and select "Product tour".
        await onboardingPage.startProductTourFromNav();

        // Navigation carries the onboarding param to the flow route.
        await onboardingPage.verifyOnProvidersPageWithOnboardingParam();

        // The tour started despite the existing completion record.
        await onboardingPage.verifyTriggerAnchorPresent();
      },
    );
  });
});
