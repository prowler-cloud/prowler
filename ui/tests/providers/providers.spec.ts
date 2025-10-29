import { test } from "@playwright/test";
import { ScansPage } from "../scans/scans-page";
import {
  ProvidersPage,
  AWSProviderData,
  AWSProviderCredential,
  AWS_CREDENTIAL_OPTIONS
} from "./providers-page";


test.describe.serial("Add AWS Provider", () => {
  // Providers page object
  let providersPage: ProvidersPage;
  let scansPage: ScansPage;
  // Test data from environment variables
  const accountId = process.env.E2E_AWS_PROVIDER_ACCOUNT_ID;
  const accessKey = process.env.E2E_AWS_PROVIDER_ACCESS_KEY;
  const secretKey = process.env.E2E_AWS_PROVIDER_SECRET_KEY;
  const roleArn = process.env.E2E_AWS_PROVIDER_ROLE_ARN;

  // Validate required environment variables
  if (!accountId) {
    throw new Error(
      "E2E_AWS_PROVIDER_ACCOUNT_ID environment variable is not set",
    );
  }

  // Setup before each test
  test.beforeEach(async ({ page }) => {
    providersPage = new ProvidersPage(page);
    // Clean up existing provider to ensure clean test state
    await providersPage.deleteProviderIfExists(accountId);
  });

  // Use admin authentication for provider management
  test.use({ storageState: "playwright/.auth/admin_user.json" });

  test(
    "should add a new AWS provider with static credentials",
    {
      tag: [
        "@critical",
        "@e2e",
        "@providers",
        "@aws",
        "@serial",
        "@PROVIDER-E2E-001",
      ],
    },
    async ({ page }) => {
      // Validate required environment variables
      if (!accountId || !accessKey || !secretKey) {
        throw new Error(
          "E2E_AWS_PROVIDER_ACCOUNT_ID, E2E_AWS_PROVIDER_ACCESS_KEY, and E2E_AWS_PROVIDER_SECRET_KEY environment variables are not set",
        );
      }

      // Prepare test data for AWS provider
      const awsProviderData: AWSProviderData = {
        accountId: accountId,
        alias: "Test E2E AWS Account - Credentials",
      };

      // Prepare static credentials
      const staticCredentials: AWSProviderCredential = {
        type: AWS_CREDENTIAL_OPTIONS.AWS_CREDENTIALS,
        accessKeyId: accessKey,
        secretAccessKey: secretKey,
      };

      // Navigate to providers page
      await providersPage.goto();
      await providersPage.verifyPageLoaded();

      // Start adding new provider
      await providersPage.clickAddProvider();
      await providersPage.verifyConnectAccountPageLoaded();

      // Select AWS provider
      await providersPage.selectAWSProvider();

      // Fill provider details
      await providersPage.fillAWSProviderDetails(awsProviderData);
      await providersPage.clickNext();

      // Select static credentials type
      await providersPage.selectCredentialsType(
        AWS_CREDENTIAL_OPTIONS.AWS_CREDENTIALS,
      );
      await providersPage.verifyCredentialsPageLoaded();

      // Fill static credentials
      await providersPage.fillStaticCredentials(staticCredentials);
      await providersPage.clickNext();

      // Launch scan
      await providersPage.verifyLaunchScanPageLoaded();
      await providersPage.clickNext();

      // Wait for redirect to provider page
      scansPage = new ScansPage(page);
      await scansPage.verifyPageLoaded();
    },
  );

  test(
    "should add a new AWS provider with assume role credentials with Access Key and Secret Key",
    {
      tag: [
        "@critical",
        "@e2e",
        "@providers",
        "@aws",
        "@serial",
        "@PROVIDER-E2E-002",
      ],
    },
    async ({ page }) => {
      // Validate required environment variables
      if (!accountId || !accessKey || !secretKey || !roleArn) {
        throw new Error(
          "E2E_AWS_PROVIDER_ACCOUNT_ID, E2E_AWS_PROVIDER_ACCESS_KEY, E2E_AWS_PROVIDER_SECRET_KEY, and E2E_AWS_PROVIDER_ROLE_ARN environment variables are not set",
        );
      }

      // Prepare test data for AWS provider
      const awsProviderData: AWSProviderData = {
        accountId: accountId,
        alias: "Test E2E AWS Account - Credentials",
      };

      // Prepare role-based credentials
      const roleCredentials: AWSProviderCredential = {
        type: AWS_CREDENTIAL_OPTIONS.AWS_ROLE_ARN,
        accessKeyId: accessKey,
        secretAccessKey: secretKey,
        roleArn: roleArn,
      };

      // Navigate to providers page
      await providersPage.goto();
      await providersPage.verifyPageLoaded();

      // Start adding new provider
      await providersPage.clickAddProvider();
      await providersPage.verifyConnectAccountPageLoaded();

      // Select AWS provider
      await providersPage.selectAWSProvider();

      // Fill provider details
      await providersPage.fillAWSProviderDetails(awsProviderData);
      await providersPage.clickNext();

      // Select role credentials type
      await providersPage.selectCredentialsType(
        AWS_CREDENTIAL_OPTIONS.AWS_ROLE_ARN,
      );
      await providersPage.verifyCredentialsPageLoaded();

      // Fill role credentials
      await providersPage.fillRoleCredentials(roleCredentials);
      await providersPage.clickNext();

      // Launch scan
      await providersPage.verifyLaunchScanPageLoaded();
      await providersPage.clickNext();

      // Wait for redirect to provider page
      scansPage = new ScansPage(page);
      await scansPage.verifyPageLoaded();
    },
  );
});

