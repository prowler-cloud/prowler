import { test } from "@playwright/test";

import { addAWSProvider, deleteProviderIfExists } from "../helpers";
import { ProvidersPage } from "../providers/providers-page";
import { OnboardingPage } from "./onboarding-page";

// Real AWS credentials for the hasProviders false→true flip; tests skip when unset.
const accountId = process.env.E2E_AWS_PROVIDER_ACCOUNT_ID ?? "";
const accessKey = process.env.E2E_AWS_PROVIDER_ACCESS_KEY ?? "";
const secretKey = process.env.E2E_AWS_PROVIDER_SECRET_KEY ?? "";
const hasAwsCredentials = Boolean(accountId && accessKey && secretKey);

// Guided onboarding is a Prowler Cloud-only feature; it never mounts in OSS.
const isCloudEnv = process.env.NEXT_PUBLIC_IS_CLOUD_ENV === "true";

test.describe("Onboarding", () => {
  test.skip(
    !isCloudEnv,
    "Guided onboarding is a Prowler Cloud-only feature (NEXT_PUBLIC_IS_CLOUD_ENV != true)",
  );
  test.use({ storageState: "playwright/.auth/admin_user.json" });

  test.describe("Mandatory new-user path", () => {
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

        await onboardingPage.goto("/providers");
        await onboardingPage.verifyWelcomeModalVisible();
        await onboardingPage.clickGetStarted();
        await onboardingPage.verifyOnProvidersPage();
        await onboardingPage.verifyTriggerAnchorPresent();
      },
    );
  });

  test.describe("Restart path", () => {
    test.beforeEach(async ({ page }) => {
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

        await onboardingPage.goto("/providers");
        await onboardingPage.selectTourFlow("Add your first provider");
        await onboardingPage.verifyOnProvidersPageWithOnboardingParam();
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

        await onboardingPage.goto("/providers");
        await onboardingPage.verifyWelcomeModalVisible();

        // Connect a provider to drive the genuine hasProviders false→true flip.
        await addAWSProvider(page, accountId, accessKey, secretKey);

        await onboardingPage.verifyCheckpointDialogVisible();
        await onboardingPage.clickCheckpointContinue();

        await onboardingPage.verifyOnScansPage();
        await onboardingPage.verifyViewFirstScanAnchorPresent();
        await onboardingPage.closeActiveTour();

        await onboardingPage.verifyExploreFindingsAnchorPresent();

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

        await onboardingPage.verifyOnScansPage();
        await onboardingPage.closeActiveTour();
        await onboardingPage.verifyExploreFindingsAnchorPresent();
        await onboardingPage.closeActiveTour();

        // Closing the tour stops the sequence — no auto-advance to compliance.
        await onboardingPage.verifyStillOnFindingsPage();

        // Ephemeral sequence must not resume after a hard reload.
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

        // Hard reload resets the ephemeral slice; provider is connected so the gate stays silent.
        await onboardingPage.refresh();
        await onboardingPage.verifyNoDriverPopover();
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

        await onboardingPage.tourFlowMenuItem("Explore your findings").click();
        await onboardingPage.verifyOnFindingsReplayPage();
        await onboardingPage.verifyExploreFindingsAnchorPresent();

        // Replay must not chain to the next flow on close.
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

        await onboardingPage.goto("/attack-paths?onboarding=attack-paths");
        await onboardingPage.verifyOnAttackPathsPage();
        await onboardingPage.verifySingleDriverPopover();
      },
    );
  });
});
