import { test } from "@playwright/test";
import { ScansPage } from "../scans/scans-page";
import {
  ProvidersPage,
  AWSProviderData,
  AWSProviderCredential,
  AWS_CREDENTIAL_OPTIONS,
  AZUREProviderData,
  AZUREProviderCredential,
  AZURE_CREDENTIAL_OPTIONS,
  M365ProviderData,
  M365ProviderCredential,
  M365_CREDENTIAL_OPTIONS,
  KubernetesProviderData,
  KubernetesProviderCredential,
  KUBERNETES_CREDENTIAL_OPTIONS,
  GCPProviderData,
  GCPProviderCredential,
  GCP_CREDENTIAL_OPTIONS,
  GitHubProviderData,
  GitHubProviderCredential,
  GITHUB_CREDENTIAL_OPTIONS,
} from "./providers-page";
import fs from "fs";

test.describe("Add Provider", () => {
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

  test.describe.serial("Add AZURE Provider", () => {
    // Providers page object
    let providersPage: ProvidersPage;
    let scansPage: ScansPage;

    // Test data from environment variables
    const subscriptionId = process.env.E2E_AZURE_SUBSCRIPTION_ID;
    const clientId = process.env.E2E_AZURE_CLIENT_ID;
    const clientSecret = process.env.E2E_AZURE_SECRET_ID;
    const tenantId = process.env.E2E_AZURE_TENANT_ID;

    // Validate required environment variables
    if (!subscriptionId || !clientId || !clientSecret || !tenantId) {
      throw new Error(
        "E2E_AZURE_SUBSCRIPTION_ID, E2E_AZURE_CLIENT_ID, E2E_AZURE_SECRET_ID, and E2E_AZURE_TENANT_ID environment variables are not set",
      );
    }

    // Setup before each test
    test.beforeEach(async ({ page }) => {
      providersPage = new ProvidersPage(page);
      // Clean up existing provider to ensure clean test state
      await providersPage.deleteProviderIfExists(subscriptionId);
    });

    // Use admin authentication for provider management
    test.use({ storageState: "playwright/.auth/admin_user.json" });

    test(
      "should add a new Azure provider with static credentials",
      {
        tag: [
          "@critical",
          "@e2e",
          "@providers",
          "@azure",
          "@serial",
          "@PROVIDER-E2E-003",
        ],
      },
      async ({ page }) => {
        // Prepare test data for AZURE provider
        const azureProviderData: AZUREProviderData = {
          subscriptionId: subscriptionId,
          alias: "Test E2E AZURE Account - Credentials",
        };

        // Prepare static credentials
        const azureCredentials: AZUREProviderCredential = {
          type: AZURE_CREDENTIAL_OPTIONS.AZURE_CREDENTIALS,
          clientId: clientId,
          clientSecret: clientSecret,
          tenantId: tenantId,
        };

        // Navigate to providers page
        await providersPage.goto();
        await providersPage.verifyPageLoaded();

        // Start adding new provider
        await providersPage.clickAddProvider();
        await providersPage.verifyConnectAccountPageLoaded();

        // Select AZURE provider
        await providersPage.selectAZUREProvider();

        // Fill provider details
        await providersPage.fillAZUREProviderDetails(azureProviderData);
        await providersPage.clickNext();

        // Fill static credentials details
        await providersPage.fillAZURECredentials(azureCredentials);
        await providersPage.clickNext();

        // Launch scan
        await providersPage.verifyLaunchScanPageLoaded();
        await providersPage.clickNext();

        // Wait for redirect to scan page
        scansPage = new ScansPage(page);
        await scansPage.verifyPageLoaded();
      },
    );
  });

  test.describe.serial("Add M365 Provider", () => {
    // Providers page object
    let providersPage: ProvidersPage;
    let scansPage: ScansPage;

    // Test data from environment variables
    const domainId = process.env.E2E_M365_DOMAIN_ID;
    const clientId = process.env.E2E_M365_CLIENT_ID;
    const tenantId = process.env.E2E_M365_TENANT_ID;

    // Validate required environment variables
    if (!domainId || !clientId || !tenantId) {
      throw new Error(
        "E2E_M365_DOMAIN_ID, E2E_M365_CLIENT_ID, and E2E_M365_TENANT_ID environment variables are not set",
      );
    }

    // Setup before each test
    test.beforeEach(async ({ page }) => {
      providersPage = new ProvidersPage(page);
      // Clean up existing provider to ensure clean test state
      await providersPage.deleteProviderIfExists(domainId);
    });

    // Use admin authentication for provider management
    test.use({ storageState: "playwright/.auth/admin_user.json" });

    test(
      "should add a new M365 provider with static credentials",
      {
        tag: [
          "@critical",
          "@e2e",
          "@providers",
          "@m365",
          "@serial",
          "@PROVIDER-E2E-004",
        ],
      },
      async ({ page }) => {
        // Validate required environment variables
        const clientSecret = process.env.E2E_M365_SECRET_ID;

        if (!clientSecret) {
          throw new Error("E2E_M365_SECRET_ID environment variable is not set");
        }
        // Prepare test data for M365 provider
        const m365ProviderData: M365ProviderData = {
          domainId: domainId,
          alias: "Test E2E M365 Account - Credentials",
        };

        // Prepare static credentials
        const m365Credentials: M365ProviderCredential = {
          type: M365_CREDENTIAL_OPTIONS.M365_CREDENTIALS,
          clientId: clientId,
          clientSecret: clientSecret,
          tenantId: tenantId,
        };

        // Navigate to providers page
        await providersPage.goto();
        await providersPage.verifyPageLoaded();

        // Start adding new provider
        await providersPage.clickAddProvider();
        await providersPage.verifyConnectAccountPageLoaded();

        // Select M365 provider
        await providersPage.selectM365Provider();

        // Fill provider details
        await providersPage.fillM365ProviderDetails(m365ProviderData);
        await providersPage.clickNext();

        // Select static credentials type
        await providersPage.selectM365CredentialsType(
          M365_CREDENTIAL_OPTIONS.M365_CREDENTIALS,
        );

        // Verify M365 credentials page is loaded
        await providersPage.verifyM365CredentialsPageLoaded();

        // Fill static credentials details
        await providersPage.fillM365Credentials(m365Credentials);
        await providersPage.clickNext();

        // Launch scan
        await providersPage.verifyLaunchScanPageLoaded();
        await providersPage.clickNext();

        // Wait for redirect to scan page
        scansPage = new ScansPage(page);
        await scansPage.verifyPageLoaded();
      },
    );

    test(
      "should add a new M365 provider with certificate",
      {
        tag: [
          "@critical",
          "@e2e",
          "@providers",
          "@m365",
          "@serial",
          "@PROVIDER-E2E-005",
        ],
      },
      async ({ page }) => {
        // Validate required environment variables
        const certificateContent = process.env.E2E_M365_CERTIFICATE_CONTENT;

        if (!certificateContent) {
          throw new Error(
            "E2E_M365_CERTIFICATE_CONTENT environment variable is not set",
          );
        }

        // Prepare test data for M365 provider
        const m365ProviderData: M365ProviderData = {
          domainId: domainId,
          alias: "Test E2E M365 Account - Certificate",
        };

        // Prepare static credentials
        const m365Credentials: M365ProviderCredential = {
          type: M365_CREDENTIAL_OPTIONS.M365_CERTIFICATE_CREDENTIALS,
          clientId: clientId,
          tenantId: tenantId,
          certificateContent: certificateContent,
        };

        // Navigate to providers page
        await providersPage.goto();
        await providersPage.verifyPageLoaded();

        // Start adding new provider
        await providersPage.clickAddProvider();
        await providersPage.verifyConnectAccountPageLoaded();

        // Select M365 provider
        await providersPage.selectM365Provider();

        // Fill provider details
        await providersPage.fillM365ProviderDetails(m365ProviderData);
        await providersPage.clickNext();

        // Select static credentials type
        await providersPage.selectM365CredentialsType(
          M365_CREDENTIAL_OPTIONS.M365_CERTIFICATE_CREDENTIALS,
        );

        // Verify M365 certificate credentials page is loaded
        await providersPage.verifyM365CertificateCredentialsPageLoaded();

        // Fill static credentials details
        await providersPage.fillM365CertificateCredentials(m365Credentials);
        await providersPage.clickNext();

        // Launch scan
        await providersPage.verifyLaunchScanPageLoaded();
        await providersPage.clickNext();

        // Wait for redirect to scan page
        scansPage = new ScansPage(page);
        await scansPage.verifyPageLoaded();
      },
    );
  });

  test.describe.serial("Add Kubernetes Provider", () => {
    // Providers page object
    let providersPage: ProvidersPage;
    let scansPage: ScansPage;

    // Test data from environment variables
    const context = process.env.E2E_KUBERNETES_CONTEXT;
    const kubeconfigPath = process.env.E2E_KUBERNETES_KUBECONFIG_PATH;

    // Validate required environment variables
    if (!context || !kubeconfigPath) {
      throw new Error(
        "E2E_KUBERNETES_CONTEXT and E2E_KUBERNETES_KUBECONFIG_PATH environment variables are not set",
      );
    }


    // Setup before each test
    test.beforeEach(async ({ page }) => {
      providersPage = new ProvidersPage(page);
      // Clean up existing provider to ensure clean test state
      await providersPage.deleteProviderIfExists(context);
    });

    // Use admin authentication for provider management
    test.use({ storageState: "playwright/.auth/admin_user.json" });

    test(
      "should add a new Kubernetes provider with kubeconfig context",
      {
        tag: [
          "@critical",
          "@e2e",
          "@providers",
          "@kubernetes",
          "@serial",
          "@PROVIDER-E2E-006",
        ],
      },
      async ({ page }) => {
        // Verify kubeconfig file exists
        if (!fs.existsSync(kubeconfigPath)) {
          throw new Error(`Kubeconfig file not found at ${kubeconfigPath}`);
        }

        // Read kubeconfig content from file
        let kubeconfigContent: string;
        try {
          kubeconfigContent = fs.readFileSync(kubeconfigPath, "utf8");
        } catch (error) {
          throw new Error(
            `Failed to read kubeconfig file at ${kubeconfigPath}: ${error}`,
          );
        }

        // Prepare test data for Kubernetes provider
        const kubernetesProviderData: KubernetesProviderData = {
          context: context,
          alias: "Test E2E Kubernetes Account - Kubeconfig Context",
        };

        // Prepare static credentials
        const kubernetesCredentials: KubernetesProviderCredential = {
          type: KUBERNETES_CREDENTIAL_OPTIONS.KUBECONFIG_CONTENT,
          kubeconfigContent: kubeconfigContent,
        };

        // Navigate to providers page
        await providersPage.goto();
        await providersPage.verifyPageLoaded();

        // Start adding new provider
        await providersPage.clickAddProvider();
        await providersPage.verifyConnectAccountPageLoaded();

        // Select Kubernetes provider
        await providersPage.selectKubernetesProvider();

        // Fill provider details
        await providersPage.fillKubernetesProviderDetails(
          kubernetesProviderData,
        );
        await providersPage.clickNext();

        // Verify credentials page is loaded
        await providersPage.verifyKubernetesCredentialsPageLoaded();

        // Fill static credentials details
        await providersPage.fillKubernetesCredentials(kubernetesCredentials);
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

  test.describe.serial("Add GCP Provider", () => {
    // Providers page object
    let providersPage: ProvidersPage;
    let scansPage: ScansPage;

    // Test data from environment variables
    const projectId = process.env.E2E_GCP_PROJECT_ID;

    // Validate required environment variables
    if (!projectId) {
      throw new Error("E2E_GCP_PROJECT_ID environment variable is not set");
    }

    // Setup before each test
    test.beforeEach(async ({ page }) => {
      providersPage = new ProvidersPage(page);
      // Clean up existing provider to ensure clean test state
      await providersPage.deleteProviderIfExists(projectId);
    });

    // Use admin authentication for provider management
    test.use({ storageState: "playwright/.auth/admin_user.json" });

    test(
      "should add a new GCP provider with service account key",
      {
        tag: [
          "@critical",
          "@e2e",
          "@providers",
          "@gcp",
          "@serial",
          "@PROVIDER-E2E-007",
        ],
      },
      async ({ page }) => {
        // Validate required environment variables
        const serviceAccountKeyB64 =
          process.env.E2E_GCP_BASE64_SERVICE_ACCOUNT_KEY;

        // Verify service account key is base64 encoded
        if (!serviceAccountKeyB64) {
          throw new Error(
            "E2E_GCP_BASE64_SERVICE_ACCOUNT_KEY environment variable is not set",
          );
        }

        // Decode service account key from base64
        const serviceAccountKey = Buffer.from(
          serviceAccountKeyB64,
          "base64",
        ).toString("utf8");

        // Verify service account key is valid JSON
        if (!JSON.parse(serviceAccountKey)) {
          throw new Error("Invalid service account key format");
        }

        // Prepare test data for GCP provider
        const gcpProviderData: GCPProviderData = {
          projectId: projectId,
          alias: "Test E2E GCP Account - Service Account Key",
        };

        // Prepare static credentials
        const gcpCredentials: GCPProviderCredential = {
          type: GCP_CREDENTIAL_OPTIONS.GCP_SERVICE_ACCOUNT,
          serviceAccountKey: serviceAccountKey,
        };

        // Navigate to providers page
        await providersPage.goto();
        await providersPage.verifyPageLoaded();

        // Start adding new provider
        await providersPage.clickAddProvider();
        await providersPage.verifyConnectAccountPageLoaded();

        // Select M365 provider
        await providersPage.selectGCPProvider();

        // Fill provider details
        await providersPage.fillGCPProviderDetails(gcpProviderData);
        await providersPage.clickNext();

        // Select static credentials type
        await providersPage.selectGCPCredentialsType(
          GCP_CREDENTIAL_OPTIONS.GCP_SERVICE_ACCOUNT,
        );

        // Verify GCP service account page is loaded
        await providersPage.verifyGCPServiceAccountPageLoaded();

        // Fill static service account key details
        await providersPage.fillGCPServiceAccountKeyCredentials(gcpCredentials);
        await providersPage.clickNext();

        // Launch scan
        await providersPage.verifyLaunchScanPageLoaded();
        await providersPage.clickNext();

        // Wait for redirect to scan page
        scansPage = new ScansPage(page);
        await scansPage.verifyPageLoaded();
      },
    );
  });

  test.describe.serial("Add GitHub Provider", () => {
    // Providers page object
    let providersPage: ProvidersPage;
    let scansPage: ScansPage;

    test.describe("Add GitHub provider with username", () => {
      // Test data from environment variables
      const username = process.env.E2E_GITHUB_USERNAME;

      // Validate required environment variables
      if (!username) {
        throw new Error("E2E_GITHUB_USERNAME environment variable is not set");
      }

      // Setup before each test
      test.beforeEach(async ({ page }) => {
        providersPage = new ProvidersPage(page);
        // Clean up existing provider to ensure clean test state
        await providersPage.deleteProviderIfExists(username);
      });

      // Use admin authentication for provider management
      test.use({ storageState: "playwright/.auth/admin_user.json" });

      test(
        "should add a new GitHub provider with personal access token",
        {
          tag: [
            "@critical",
            "@e2e",
            "@providers",
            "@github",
            "@serial",
            "@PROVIDER-E2E-008",
          ],
        },
        async ({ page }) => {
          // Validate required environment variables
          const personalAccessToken =
            process.env.E2E_GITHUB_PERSONAL_ACCESS_TOKEN;

          // Verify username and personal access token are set in environment variables
          if (!personalAccessToken) {
            throw new Error(
              "E2E_GITHUB_PERSONAL_ACCESS_TOKEN environment variables are not set",
            );
          }

          // Prepare test data for GitHub provider
          const githubProviderData: GitHubProviderData = {
            username: username,
            alias: "Test E2E GitHub Account - Personal Access Token",
          };

          // Prepare personal access token credentials
          const githubCredentials: GitHubProviderCredential = {
            type: GITHUB_CREDENTIAL_OPTIONS.GITHUB_PERSONAL_ACCESS_TOKEN,
            personalAccessToken: personalAccessToken,
          };

          // Navigate to providers page
          await providersPage.goto();
          await providersPage.verifyPageLoaded();

          // Start adding new provider
          await providersPage.clickAddProvider();
          await providersPage.verifyConnectAccountPageLoaded();

          // Select GitHub provider
          await providersPage.selectGitHubProvider();

          // Fill provider details
          await providersPage.fillGitHubProviderDetails(githubProviderData);
          await providersPage.clickNext();

          // Select GitHub personal access token credentials type
          await providersPage.selectGitHubCredentialsType(
            GITHUB_CREDENTIAL_OPTIONS.GITHUB_PERSONAL_ACCESS_TOKEN,
          );

          // Verify GitHub personal access token page is loaded
          await providersPage.verifyGitHubPersonalAccessTokenPageLoaded();

          // Fill static personal access token details
          await providersPage.fillGitHubPersonalAccessTokenCredentials(
            githubCredentials,
          );
          await providersPage.clickNext();

          // Launch scan
          await providersPage.verifyLaunchScanPageLoaded();
          await providersPage.clickNext();

          // Wait for redirect to scan page
          scansPage = new ScansPage(page);
          await scansPage.verifyPageLoaded();
        },
      );
      test(
        "should add a new GitHub provider with github app",
        {
          tag: [
            "@critical",
            "@e2e",
            "@providers",
            "@github",
            "@serial",
            "@PROVIDER-E2E-009",
          ],
        },
        async ({ page }) => {
          // Validate required environment variables
          const githubAppId =
            process.env.E2E_GITHUB_APP_ID;
          const githubAppPrivateKeyB64 =
            process.env.E2E_GITHUB_BASE64_APP_PRIVATE_KEY;

          // Verify github app id and private key are set in environment variables
          if (!githubAppId || !githubAppPrivateKeyB64) {
            throw new Error(
              "E2E_GITHUB_APP_ID and E2E_GITHUB_APP_PRIVATE_KEY environment variables are not set",
            );
          }
          // Decode github app private key from base64
          const githubAppPrivateKey = Buffer.from(
            githubAppPrivateKeyB64,
            "base64",
          ).toString("utf8");

          // Prepare test data for GitHub provider
          const githubProviderData: GitHubProviderData = {
            username: username,
            alias: "Test E2E GitHub Account - GitHub App",
          };

          // Prepare github app credentials
          const githubCredentials: GitHubProviderCredential = {
            type: GITHUB_CREDENTIAL_OPTIONS.GITHUB_APP,
            githubAppId: githubAppId,
            githubAppPrivateKey: githubAppPrivateKey,
          };

          // Navigate to providers page
          await providersPage.goto();
          await providersPage.verifyPageLoaded();

          // Start adding new provider
          await providersPage.clickAddProvider();
          await providersPage.verifyConnectAccountPageLoaded();

          // Select GitHub provider
          await providersPage.selectGitHubProvider();

          // Fill provider details
          await providersPage.fillGitHubProviderDetails(githubProviderData);
          await providersPage.clickNext();

          // Select static github app credentials type
          await providersPage.selectGitHubCredentialsType(
            GITHUB_CREDENTIAL_OPTIONS.GITHUB_APP,
          );

          // Verify GitHub github app page is loaded
          await providersPage.verifyGitHubAppPageLoaded();

          // Fill static github app credentials details
          await providersPage.fillGitHubAppCredentials(
            githubCredentials,
          );
          await providersPage.clickNext();

          // Launch scan
          await providersPage.verifyLaunchScanPageLoaded();
          await providersPage.clickNext();

          // Wait for redirect to scan page
          scansPage = new ScansPage(page);
          await scansPage.verifyPageLoaded();
        },
      );
    });
    test.describe("Add GitHub provider with organization", () => {
      // Test data from environment variables
      const organization = process.env.E2E_GITHUB_ORGANIZATION;

      // Validate required environment variables
      if (!organization) {
        throw new Error(
          "E2E_GITHUB_ORGANIZATION environment variable is not set",
        );
      }

      // Setup before each test
      test.beforeEach(async ({ page }) => {
        providersPage = new ProvidersPage(page);
        // Clean up existing provider to ensure clean test state
        await providersPage.deleteProviderIfExists(organization);
      });

      // Use admin authentication for provider management
      test.use({ storageState: "playwright/.auth/admin_user.json" });
      test(
        "should add a new GitHub provider with organization personal access token",
        {
          tag: [
            "@critical",
            "@e2e",
            "@providers",
            "@github",
            "@serial",
            "@PROVIDER-E2E-010",
          ],
        },
        async ({ page }) => {
          // Validate required environment variables
          const organizationAccessToken =
            process.env.E2E_GITHUB_ORGANIZATION_ACCESS_TOKEN;

          // Verify username and personal access token are set in environment variables
          if (!organizationAccessToken) {
            throw new Error(
              "E2E_GITHUB_ORGANIZATION_ACCESS_TOKEN environment variables are not set",
            );
          }

          // Prepare test data for GitHub provider
          const githubProviderData: GitHubProviderData = {
            username: organization,
            alias: "Test E2E GitHub Account - Organization Access Token",
          };

          // Prepare personal access token credentials
          const githubCredentials: GitHubProviderCredential = {
            type: GITHUB_CREDENTIAL_OPTIONS.GITHUB_PERSONAL_ACCESS_TOKEN,
            personalAccessToken: organizationAccessToken,
          };

          // Navigate to providers page
          await providersPage.goto();
          await providersPage.verifyPageLoaded();

          // Start adding new provider
          await providersPage.clickAddProvider();
          await providersPage.verifyConnectAccountPageLoaded();

          // Select GitHub provider
          await providersPage.selectGitHubProvider();

          // Fill provider details
          await providersPage.fillGitHubProviderDetails(githubProviderData);
          await providersPage.clickNext();

          // Select GitHub organization personal access token credentials type
          await providersPage.selectGitHubCredentialsType(
            GITHUB_CREDENTIAL_OPTIONS.GITHUB_PERSONAL_ACCESS_TOKEN,
          );

          // Verify GitHub personal access token page is loaded
          await providersPage.verifyGitHubPersonalAccessTokenPageLoaded();

          // Fill static personal access token details
          await providersPage.fillGitHubPersonalAccessTokenCredentials(
            githubCredentials,
          );
          await providersPage.clickNext();

          // Launch scan
          await providersPage.verifyLaunchScanPageLoaded();
          await providersPage.clickNext();

          // Wait for redirect to scan page
          scansPage = new ScansPage(page);
          await scansPage.verifyPageLoaded();
        },
      );
    });
  });
});
