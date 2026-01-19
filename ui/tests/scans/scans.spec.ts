import { test } from "@playwright/test";
import { ScansPage } from "./scans-page";
import { ProvidersPage } from "../providers/providers-page";
import { deleteProviderIfExists, addAWSProvider } from "../helpers";

// Scans E2E suite scaffold
test.describe("Scans", () => {
  test.describe.serial("Execute Scans", () => {
    // Scans page object
    let scansPage: ScansPage;

    // Use scans-specific authenticated user
    test.use({ storageState: "playwright/.auth/admin_user.json" });

    // Before each scans test, ensure an AWS provider exists using admin context
    test.beforeEach(async ({ page }) => {
      // Create scans page object
      const providersPage = new ProvidersPage(page);

      // Test data from environment variables
      const accountId = process.env.E2E_AWS_PROVIDER_ACCOUNT_ID;
      const accessKey = process.env.E2E_AWS_PROVIDER_ACCESS_KEY;
      const secretKey = process.env.E2E_AWS_PROVIDER_SECRET_KEY;

      if (!accountId || !accessKey || !secretKey) {
        throw new Error(
          "E2E_AWS_PROVIDER_ACCOUNT_ID, E2E_AWS_PROVIDER_ACCESS_KEY, and E2E_AWS_PROVIDER_SECRET_KEY environment variables are not set",
        );
      }

      // Clean up existing provider to ensure clean test state
      await deleteProviderIfExists(providersPage, accountId);
      // Add AWS provider
      await addAWSProvider(providersPage.page, accountId, accessKey, secretKey);
    });

    test(
      "should execute on demand scan",
      {
        tag: ["@e2e", "@scans", "@critical", "@serial", "@SCAN-E2E-001"],
      },
      async ({ page }) => {

        const accountId = process.env.E2E_AWS_PROVIDER_ACCOUNT_ID;

        if (!accountId) {
          throw new Error(
            "E2E_AWS_PROVIDER_ACCOUNT_ID environment variable is not set",
          );
        }

        scansPage = new ScansPage(page);
        await scansPage.goto();

        // Select provider by UID (accountId)
        await scansPage.selectProviderByUID(accountId);

        // Complete scan alias
        await scansPage.fillScanAlias("E2E Test Scan - On Demand");

        // Press start now button
        await scansPage.clickStartNowButton();

        // Verify the scan was launched
        await scansPage.verifyScanLaunched("E2E Test Scan - On Demand");


      },
    );
  });
});
