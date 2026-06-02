import { test } from "@playwright/test";

import { addAWSProvider, deleteProviderIfExists } from "../helpers";
import { ProvidersPage } from "../providers/providers-page";
import { OnboardingPage } from "./onboarding-page";

// Real AWS provider env used to drive the genuine `hasProviders` false → true
// flip. When unset, the data-dependent sequence tests skip cleanly rather than
// faking a passing assertion.
const accountId = process.env.E2E_AWS_PROVIDER_ACCOUNT_ID ?? "";
const accessKey = process.env.E2E_AWS_PROVIDER_ACCESS_KEY ?? "";
const secretKey = process.env.E2E_AWS_PROVIDER_SECRET_KEY ?? "";
const hasAwsCredentials = Boolean(accountId && accessKey && secretKey);

test.describe("Onboarding", () => {
  // Reuse admin authentication; provider management requires it and the gate
  // reads the already-hydrated `hasProviders` signal from this session.
  test.use({ storageState: "playwright/.auth/admin_user.json" });

  test.describe("Mandatory new-user path", () => {
    // The gate only fires for a zero-provider account, so the existing E2E AWS
    // provider (when configured) is removed and the tour state is cleared.
    test.beforeEach(async ({ page }) => {
      const providersPage = new ProvidersPage(page);
      if (accountId) {
        await deleteProviderIfExists(providersPage, accountId);
      }

      // Clear tour records + checkpoint marker so the gate and the checkpoint
      // watcher both evaluate as a fresh browser.
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

        // Open the avatar menu → "Product tour" submenu → select the first flow.
        await onboardingPage.selectTourFlow("Add your first provider");

        // Navigation carries the onboarding param to the flow route.
        await onboardingPage.verifyOnProvidersPageWithOnboardingParam();

        // The tour started despite the existing completion record.
        await onboardingPage.verifyTriggerAnchorPresent();
      },
    );
  });

  test.describe("Guided sequence", () => {
    test.beforeEach(async ({ page }) => {
      const providersPage = new ProvidersPage(page);
      if (accountId) {
        await deleteProviderIfExists(providersPage, accountId);
      }
      await providersPage.goto();
      const onboardingPage = new OnboardingPage(page);
      await onboardingPage.clearOnboardingState();
    });

    test(
      "runs the first-run sequence after the checkpoint and chains every flow",
      {
        tag: ["@critical", "@e2e", "@onboarding", "@OB-E2E-003"],
      },
      async ({ page }) => {
        test.skip(
          !hasAwsCredentials,
          "E2E AWS provider credentials are not set; cannot drive a real hasProviders flip",
        );

        const onboardingPage = new OnboardingPage(page);

        // Zero-provider user is gated into the Welcome modal first.
        await onboardingPage.goto("/providers");
        await onboardingPage.verifyWelcomeModalVisible();

        // Connect a provider — the genuine `false → true` hasProviders flip the
        // checkpoint watcher reacts to (never a faked localStorage flag).
        await addAWSProvider(page, accountId, accessKey, secretKey);

        // The checkpoint dialog fires once on the connected flip.
        await onboardingPage.verifyCheckpointDialogVisible();
        await onboardingPage.clickCheckpointContinue();

        // Flow 2: scans.
        await onboardingPage.verifyOnScansPage();
        await onboardingPage.verifyViewFirstScanAnchorPresent();
        await onboardingPage.closeActiveTour();

        // Flow 3: findings (advance only happens on completion; this asserts the
        // chained navigation surface — anchors/URL, never overlay animation).
        await onboardingPage.verifyExploreFindingsAnchorPresent();

        // Flows 4 and 5: compliance and attack paths anchors are reachable.
        await onboardingPage.goto("/compliance");
        await onboardingPage.verifyViewComplianceAnchorPresent();
        await onboardingPage.goto("/attack-paths");
        await onboardingPage.verifyAttackPathsAnchorPresent();
      },
    );

    test(
      "stops the sequence when a tour is closed and does not resume on reload",
      {
        tag: ["@high", "@e2e", "@onboarding", "@OB-E2E-004"],
      },
      async ({ page }) => {
        test.skip(
          !hasAwsCredentials,
          "E2E AWS provider credentials are not set; cannot drive the guided sequence",
        );

        const onboardingPage = new OnboardingPage(page);

        await onboardingPage.goto("/providers");
        await addAWSProvider(page, accountId, accessKey, secretKey);
        await onboardingPage.verifyCheckpointDialogVisible();
        await onboardingPage.clickCheckpointContinue();

        // Advance into the sequence, then jump to findings and close the tour.
        await onboardingPage.verifyOnScansPage();
        await onboardingPage.closeActiveTour();
        await onboardingPage.verifyExploreFindingsAnchorPresent();
        await onboardingPage.closeActiveTour();

        // Closing the tour ends the sequence: no auto-advance to compliance.
        await onboardingPage.verifyStillOnFindingsPage();

        // A reload must not resume the (ephemeral) sequence.
        await onboardingPage.refresh();
        await onboardingPage.verifyNoDriverPopover();
      },
    );

    test(
      "does not re-fire after a hard reload mid-sequence",
      {
        tag: ["@high", "@e2e", "@onboarding", "@OB-E2E-007"],
      },
      async ({ page }) => {
        test.skip(
          !hasAwsCredentials,
          "E2E AWS provider credentials are not set; cannot drive the guided sequence",
        );

        const onboardingPage = new OnboardingPage(page);

        await onboardingPage.goto("/providers");
        await addAWSProvider(page, accountId, accessKey, secretKey);
        await onboardingPage.verifyCheckpointDialogVisible();
        await onboardingPage.clickCheckpointContinue();
        await onboardingPage.verifyOnScansPage();

        // Hard reload resets the ephemeral slice — nothing auto-fires.
        await onboardingPage.refresh();
        await onboardingPage.verifyNoDriverPopover();
        // The provider is connected, so the gate keeps the Welcome modal closed.
        await onboardingPage.verifyWelcomeModalNotVisible();
      },
    );
  });

  test.describe("Manual replay", () => {
    test.beforeEach(async ({ page }) => {
      const onboardingPage = new OnboardingPage(page);
      await onboardingPage.goto("/providers");
      await onboardingPage.seedCompletedAddProviderRecord();
    });

    test(
      "replays a single flow from the avatar submenu without chaining",
      {
        tag: ["@high", "@e2e", "@onboarding", "@OB-E2E-005"],
      },
      async ({ page }) => {
        const onboardingPage = new OnboardingPage(page);

        await onboardingPage.goto("/providers");

        // The submenu lists every registry flow by title.
        await onboardingPage.openProductTourSubmenu();
        for (const title of [
          "Add your first provider",
          "Run your first scan",
          "Explore your findings",
          "Check compliance",
          "Visualize attack paths",
        ]) {
          await onboardingPage.verifyElementVisible(
            onboardingPage.tourFlowMenuItem(title),
          );
        }

        // Selecting one replays that single flow only.
        await onboardingPage.tourFlowMenuItem("Explore your findings").click();
        await onboardingPage.verifyOnFindingsReplayPage();
        await onboardingPage.verifyExploreFindingsAnchorPresent();

        // Closing the replayed tour does NOT advance to the next flow.
        await onboardingPage.closeActiveTour();
        await onboardingPage.verifyStillOnFindingsPage();
      },
    );
  });

  test.describe("Attack-paths single-fire", () => {
    test(
      "renders exactly one driver popover on the attack-paths route",
      {
        tag: ["@high", "@e2e", "@onboarding", "@OB-E2E-006"],
      },
      async ({ page }) => {
        test.skip(
          !hasAwsCredentials,
          "E2E AWS provider credentials are not set; attack-paths needs a ready scan",
        );

        const onboardingPage = new OnboardingPage(page);

        // The page owns the driver; onboarding must not mount a second runner.
        await onboardingPage.goto("/attack-paths?onboarding=attack-paths");
        await onboardingPage.verifyOnAttackPathsPage();
        await onboardingPage.verifySingleDriverPopover();
      },
    );
  });
});
