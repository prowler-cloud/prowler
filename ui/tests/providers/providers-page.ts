import { Page, Locator, expect } from "@playwright/test";
import { BasePage } from "../base-page";

// AWS provider data
export interface AWSProviderData {
  accountId: string;
  alias?: string;
  roleArn?: string;
  externalId?: string;
  accessKeyId?: string;
  secretAccessKey?: string;
}

// AZURE provider data
export interface AZUREProviderData {
  subscriptionId: string;
  alias?: string;
}

// M365 provider data
export interface M365ProviderData {
  domainId: string;
  alias?: string;
}

// Kubernetes provider data
export interface KubernetesProviderData {
  context: string;
  alias?: string;
}

// AWS credential options
export const AWS_CREDENTIAL_OPTIONS = {
  AWS_ROLE_ARN: "role",
  AWS_CREDENTIALS: "credentials",
} as const;

// AWS credential type
type AWSCredentialType =
  (typeof AWS_CREDENTIAL_OPTIONS)[keyof typeof AWS_CREDENTIAL_OPTIONS];

// AWS provider credential
export interface AWSProviderCredential {
  type: AWSCredentialType;
  roleArn?: string;
  externalId?: string;
  accessKeyId?: string;
  secretAccessKey?: string;
}

// AZURE credential options
export const AZURE_CREDENTIAL_OPTIONS = {
  AZURE_CREDENTIALS: "credentials",
} as const;

// AZURE credential type
type AZURECredentialType =
  (typeof AZURE_CREDENTIAL_OPTIONS)[keyof typeof AZURE_CREDENTIAL_OPTIONS];

// AZURE provider credential
export interface AZUREProviderCredential {
  type: AZURECredentialType;
  clientId: string;
  clientSecret: string;
  tenantId: string;
}

// M365 credential options
export const M365_CREDENTIAL_OPTIONS = {
  M365_CREDENTIALS: "credentials",
  M365_CERTIFICATE_CREDENTIALS: "certificate",
} as const;

// M365 credential type
type M365CredentialType =
  (typeof M365_CREDENTIAL_OPTIONS)[keyof typeof M365_CREDENTIAL_OPTIONS];

// M365 provider credential
export interface M365ProviderCredential {
  type: M365CredentialType;
  clientId: string;
  clientSecret?: string;
  tenantId: string;
  certificateContent?: string;
}

// Kubernetes credential options
export const KUBERNETES_CREDENTIAL_OPTIONS = {
  KUBECONFIG_CONTENT: "kubeconfig"
} as const;

// Kubernetes credential type
type KubernetesCredentialType = (typeof KUBERNETES_CREDENTIAL_OPTIONS)[keyof typeof KUBERNETES_CREDENTIAL_OPTIONS];

// Kubernetes provider credential
export interface KubernetesProviderCredential {
  type: KubernetesCredentialType;
  kubeconfigContent:string;
} 

// Providers page
export class ProvidersPage extends BasePage {
  // Button to add a new cloud provider
  readonly addProviderButton: Locator;
  readonly providersTable: Locator;

  // Provider selection elements
  readonly awsProviderRadio: Locator;
  readonly gcpProviderRadio: Locator;
  readonly azureProviderRadio: Locator;
  readonly m365ProviderRadio: Locator;
  readonly kubernetesProviderRadio: Locator;
  readonly githubProviderRadio: Locator;

  // AWS provider form elements
  readonly accountIdInput: Locator;
  readonly aliasInput: Locator;
  readonly nextButton: Locator;
  readonly backButton: Locator;
  readonly saveButton: Locator;
  readonly launchScanButton: Locator;

  // AWS credentials type selection
  readonly roleCredentialsRadio: Locator;
  readonly staticCredentialsRadio: Locator;

  // M365 credentials type selection
  readonly m365StaticCredentialsRadio: Locator;
  readonly m365CertificateCredentialsRadio: Locator;

  // AWS role credentials form
  readonly roleArnInput: Locator;
  readonly externalIdInput: Locator;

  // AWS static credentials form
  readonly accessKeyIdInput: Locator;
  readonly secretAccessKeyInput: Locator;

  // AZURE provider form elements
  readonly azureSubscriptionIdInput: Locator;
  readonly azureClientIdInput: Locator;
  readonly azureClientSecretInput: Locator;
  readonly azureTenantIdInput: Locator;

  // M365 provider form elements
  readonly m365domainIdInput: Locator;
  readonly m365ClientIdInput: Locator;
  readonly m365ClientSecretInput: Locator;
  readonly m365TenantIdInput: Locator;
  readonly m365CertificateContentInput: Locator;

  // Kubernetes provider form elements
  readonly kubernetesContextInput: Locator;
  readonly kubernetesKubeconfigContentInput: Locator;

  // Delete button
  readonly deleteProviderConfirmationButton: Locator;

  constructor(page: Page) {
    super(page);

    this.addProviderButton = page.getByRole("link", {
      name: "Add Cloud Provider",
    });

    // Table displaying existing providers
    this.providersTable = page.getByRole("table");

    // Radio buttons to select the type of cloud provider
    this.awsProviderRadio = page.getByRole("radio", {
      name: /Amazon Web Services/i,
    });
    this.gcpProviderRadio = page.getByRole("radio", {
      name: /Google Cloud Platform/i,
    });
    this.azureProviderRadio = page.getByRole("radio", {
      name: /Microsoft Azure/i,
    });
    this.m365ProviderRadio = page.getByRole("radio", {
      name: /Microsoft 365/i,
    });
    this.kubernetesProviderRadio = page.getByRole("radio", {
      name: /Kubernetes/i,
    });
    this.githubProviderRadio = page.getByRole("radio", { name: /GitHub/i });

    // AWS provider form inputs
    this.accountIdInput = page.getByRole("textbox", { name: "Account ID" });

    // AZURE provider form inputs
    this.azureSubscriptionIdInput = page.getByRole("textbox", {
      name: "Subscription ID",
    });
    this.azureClientIdInput = page.getByRole("textbox", { name: "Client ID" });
    this.azureClientSecretInput = page.getByRole("textbox", {
      name: "Client Secret",
    });
    this.azureTenantIdInput = page.getByRole("textbox", { name: "Tenant ID" });

    // M365 provider form inputs
    this.m365domainIdInput = page.getByRole("textbox", { name: "Domain ID" });
    this.m365ClientIdInput = page.getByRole("textbox", { name: "Client ID" });
    this.m365ClientSecretInput = page.getByRole("textbox", {
      name: "Client Secret",
    });
    this.m365TenantIdInput = page.getByRole("textbox", { name: "Tenant ID" });
    this.m365CertificateContentInput = page.getByRole("textbox", { name: "Certificate Content" });

    // Kubernetes provider form inputs
    this.kubernetesContextInput = page.getByRole("textbox", { name: "Context" });
    this.kubernetesKubeconfigContentInput = page.getByRole("textbox", { name: "Kubeconfig Content" });
    
    // Alias input
    this.aliasInput = page.getByRole("textbox", {
      name: "Provider alias (optional)",
    });

    // Navigation buttons in the form (next and back)
    this.nextButton = page
      .locator("form")
      .getByRole("button", { name: "Next", exact: true });
    this.backButton = page.getByRole("button", { name: "Back" });

    // Button to save the form
    this.saveButton = page.getByRole("button", { name: "Save", exact: true });

    // Button to launch a scan
    this.launchScanButton = page.getByRole("button", {
      name: "Launch scan",
      exact: true,
    });

    // Radios for selecting AWS credentials method
    this.roleCredentialsRadio = page.getByRole("radio", {
      name: /Connect assuming IAM Role/i,
    });
    this.staticCredentialsRadio = page.getByRole("radio", {
      name: /Connect via Credentials/i,
    });

    // Radios for selecting M365 credentials method
    this.m365StaticCredentialsRadio = page.getByRole("radio", {
      name: /App Client Secret Credentials/i,
    });
    this.m365CertificateCredentialsRadio = page.getByRole("radio", {
      name: /App Certificate Credentials/i,
    });

    // Inputs for IAM Role credentials
    this.roleArnInput = page.getByRole("textbox", { name: "Role ARN" });
    this.externalIdInput = page.getByRole("textbox", { name: "External ID" });

    // Inputs for static credentials
    this.accessKeyIdInput = page.getByRole("textbox", {
      name: "Access Key ID",
    });
    this.secretAccessKeyInput = page.getByRole("textbox", {
      name: "Secret Access Key",
    });

    // Delete button in confirmation modal
    this.deleteProviderConfirmationButton = page.getByRole("button", {
      name: "Delete",
      exact: true,
    });
  }

  async goto(): Promise<void> {
    // Go to the providers page

    await super.goto("/providers");
  }

  async clickAddProvider(): Promise<void> {
    // Click the add provider button

    await this.addProviderButton.click();
  }

  async selectAWSProvider(): Promise<void> {
    // Prefer label-based click for radios, force if overlay intercepts
    await this.awsProviderRadio.click({ force: true });
  }

  async selectAZUREProvider(): Promise<void> {
    // Prefer label-based click for radios, force if overlay intercepts
    await this.azureProviderRadio.click({ force: true });
  }

  async selectM365Provider(): Promise<void> {
    // Select the M365 provider

    await this.m365ProviderRadio.click({ force: true });
  }

  async selectKubernetesProvider(): Promise<void> {
    // Select the Kubernetes provider

    await this.kubernetesProviderRadio.click({ force: true });
  }


  async fillAWSProviderDetails(data: AWSProviderData): Promise<void> {
    // Fill the AWS provider details

    await this.accountIdInput.fill(data.accountId);

    if (data.alias) {
      await this.aliasInput.fill(data.alias);
    }
  }

  async fillAZUREProviderDetails(data: AZUREProviderData): Promise<void> {
    // Fill the AWS provider details

    await this.azureSubscriptionIdInput.fill(data.subscriptionId);

    if (data.alias) {
      await this.aliasInput.fill(data.alias);
    }
  }

  async fillM365ProviderDetails(data: M365ProviderData): Promise<void> {
    // Fill the M365 provider details

    await this.m365domainIdInput.fill(data.domainId);

    if (data.alias) {
      await this.aliasInput.fill(data.alias);
    }
  }

  async fillKubernetesProviderDetails(data: KubernetesProviderData): Promise<void> {
    // Fill the Kubernetes provider details

    await this.kubernetesContextInput.fill(data.context);

    if (data.alias) {

      await this.aliasInput.fill(data.alias);
    }
  }

  async clickNext(): Promise<void> {
    // The wizard interface may use different labels for its primary action button on each step.
    // This function determines which button to click depending on the current URL and page content.

    // Get the current page URL
    const url = this.page.url();

    // If on the "connect-account" step, click the "Next" button
    if (/\/providers\/connect-account/.test(url)) {
      await this.nextButton.click();
      return;
    }

    // If on the "add-credentials" step, check for "Save" and "Next" buttons
    if (/\/providers\/add-credentials/.test(url)) {
      // Some UI implementations use "Save" instead of "Next" for primary action
      const saveBtn = this.saveButton;

      if (await saveBtn.count()) {
        await saveBtn.click();
        return;
      }
      // If "Save" is not present, try clicking the "Next" button
      if (await this.nextButton.count()) {
        await this.nextButton.click();
        return;
      }
    }

    // If on the "test-connection" step, click the "Launch scan" button
    if (/\/providers\/test-connection/.test(url)) {
      const buttonByText = this.page
        .locator("button")
        .filter({ hasText: "Launch scan" });

      await buttonByText.click();

      // Wait for either success (redirect to scans) or error message to appear
      // The error container has multiple p.text-text-error elements, we want the first one with the technical error
      const errorMessage = this.page.locator("p.text-text-error").first();

      try {
        // Wait up to 15 seconds for either the error message or redirect
        await Promise.race([
          // Wait for error message to appear
          errorMessage.waitFor({ state: "visible", timeout: 15000 }),
          // Wait for redirect to scans page (success case)
          this.page.waitForURL(/\/scans/, { timeout: 15000 }),
        ]);

        // If we're still on test-connection page, check for error
        if (/\/providers\/test-connection/.test(this.page.url())) {
          const isErrorVisible = await errorMessage
            .isVisible()
            .catch(() => false);
          if (isErrorVisible) {
            const errorText = await errorMessage.textContent();
            throw new Error(
              `Test connection failed with error: ${errorText?.trim() || "Unknown error"}`,
            );
          }
        }
      } catch (error) {
        // If timeout or other error, check if error message is present
        const isErrorVisible = await errorMessage.isVisible().catch(() => false);

        if (isErrorVisible) {
          const errorText = await errorMessage.textContent();
          throw new Error(
            `Test connection failed with error: ${errorText?.trim() || "Unknown error"}`,
          );
        }
        // Re-throw original error if no error message found
        throw error;
      }

      return;
    }

    // Fallback logic: try finding any common primary action buttons in expected order
    const candidates = [
      { name: "Next" }, // Try the "Next" button
      { name: "Save" }, // Try the "Save" button
      { name: "Launch scan" }, // Try the "Launch scan" button
      { name: /Continue|Proceed/i }, // Try "Continue" or "Proceed" (case-insensitive)
    ] as const;

    // Try each candidate name and click it if found
    for (const candidate of candidates) {
      // Try each candidate name and click it if found
      const btn = this.page.getByRole("button", {
        name: candidate.name as any,
      });

      if (await btn.count()) {
        await btn.click();
        return;
      }
    }

    // If none of the expected action buttons are present, throw an error
    throw new Error(
      "Could not find an actionable Next/Save/Launch scan button on this step",
    );
  }

  async selectCredentialsType(type: AWSCredentialType): Promise<void> {
    // Ensure we are on the add-credentials page where the selector exists

    await expect(this.page).toHaveURL(/\/providers\/add-credentials/);

    if (type === AWS_CREDENTIAL_OPTIONS.AWS_ROLE_ARN) {
      await this.roleCredentialsRadio.click({ force: true });
    } else if (type === AWS_CREDENTIAL_OPTIONS.AWS_CREDENTIALS) {
      await this.staticCredentialsRadio.click({ force: true });
    } else {
      throw new Error(`Invalid AWS credential type: ${type}`);
    }
  }

  async selectM365CredentialsType(type: M365CredentialType): Promise<void> {
    // Ensure we are on the add-credentials page where the selector exists

    await expect(this.page).toHaveURL(/\/providers\/add-credentials/);

    if (type === M365_CREDENTIAL_OPTIONS.M365_CREDENTIALS) {
      await this.m365StaticCredentialsRadio.click({ force: true });
    } else if (type === M365_CREDENTIAL_OPTIONS.M365_CERTIFICATE_CREDENTIALS) {
      await this.m365CertificateCredentialsRadio.click({ force: true });
    } else {
      throw new Error(`Invalid M365 credential type: ${type}`);
    }
  }

  async fillRoleCredentials(credentials: AWSProviderCredential): Promise<void> {
    // Fill the role credentials form

    if (credentials.accessKeyId) {
      await this.accessKeyIdInput.fill(credentials.accessKeyId);
    }
    if (credentials.secretAccessKey) {
      await this.secretAccessKeyInput.fill(credentials.secretAccessKey);
    }
    if (credentials.roleArn) {
      await this.roleArnInput.fill(credentials.roleArn);
    }
    if (credentials.externalId) {
      // External ID may be prefilled and disabled; only fill if enabled
      if (await this.externalIdInput.isEnabled()) {
        await this.externalIdInput.fill(credentials.externalId);
      }
    }
  }

  async fillStaticCredentials(
    credentials: AWSProviderCredential,
  ): Promise<void> {
    // Fill the static credentials form

    if (credentials.accessKeyId) {
      await this.accessKeyIdInput.fill(credentials.accessKeyId);
    }
    if (credentials.secretAccessKey) {
      await this.secretAccessKeyInput.fill(credentials.secretAccessKey);
    }
  }

  async fillAZURECredentials(
    credentials: AZUREProviderCredential,
  ): Promise<void> {
    // Fill the azure credentials form

    if (credentials.clientId) {
      await this.azureClientIdInput.fill(credentials.clientId);
    }
    if (credentials.clientSecret) {
      await this.azureClientSecretInput.fill(credentials.clientSecret);
    }
    if (credentials.tenantId) {
      await this.azureTenantIdInput.fill(credentials.tenantId);
    }
  }

  async fillM365Credentials(
    credentials: M365ProviderCredential,
  ): Promise<void> {
    // Fill the m365 credentials form

    if (credentials.clientId) {
      await this.m365ClientIdInput.fill(credentials.clientId);
    }
    if (credentials.clientSecret) {
      await this.m365ClientSecretInput.fill(credentials.clientSecret);
    }
    if (credentials.tenantId) {
      await this.m365TenantIdInput.fill(credentials.tenantId);
    }
  }

  async fillM365CertificateCredentials(
    credentials: M365ProviderCredential,
  ): Promise<void> {
    // Fill the m365 certificate credentials form

    if (credentials.clientId) {
      await this.m365ClientIdInput.fill(credentials.clientId);
    }
    if (credentials.certificateContent) {
      await this.m365CertificateContentInput.fill(
        credentials.certificateContent,
      );
    }
    if (credentials.tenantId) {
      await this.m365TenantIdInput.fill(credentials.tenantId);
    }
  }

  async fillKubernetesCredentials(credentials: KubernetesProviderCredential): Promise<void> {
    // Fill the Kubernetes credentials form

    if (credentials.kubeconfigContent) {
      await this.kubernetesKubeconfigContentInput.fill(credentials.kubeconfigContent);
    }
  }


  async verifyPageLoaded(): Promise<void> {
    // Verify the providers page is loaded

    await expect(this.page).toHaveTitle(/Prowler/);
    await expect(this.addProviderButton).toBeVisible();
  }

  async verifyConnectAccountPageLoaded(): Promise<void> {
    // Verify the connect account page is loaded

    await expect(this.page).toHaveTitle(/Prowler/);
    await expect(this.awsProviderRadio).toBeVisible();
  }

  async verifyCredentialsPageLoaded(): Promise<void> {
    // Verify the credentials page is loaded

    await expect(this.page).toHaveTitle(/Prowler/);
    await expect(this.roleCredentialsRadio).toBeVisible();
  }

  async verifyM365CredentialsPageLoaded(): Promise<void> {
    // Verify the M365 credentials page is loaded

    await expect(this.page).toHaveTitle(/Prowler/);
    await expect(this.m365ClientIdInput).toBeVisible();
    await expect(this.m365ClientSecretInput).toBeVisible();
    await expect(this.m365TenantIdInput).toBeVisible();
  }

  async verifyM365CertificateCredentialsPageLoaded(): Promise<void> {
    // Verify the M365 certificate credentials page is loaded

    await expect(this.page).toHaveTitle(/Prowler/);
    await expect(this.m365ClientIdInput).toBeVisible();
    await expect(this.m365TenantIdInput).toBeVisible();
    await expect(this.m365CertificateContentInput).toBeVisible();
  }

  async verifyKubernetesCredentialsPageLoaded(): Promise<void> {
    // Verify the Kubernetes credentials page is loaded

    await expect(this.page).toHaveTitle(/Prowler/);
    await expect(this.kubernetesContextInput).toBeVisible();
  }

  async verifyLaunchScanPageLoaded(): Promise<void> {
    // Verify the launch scan page is loaded

    await expect(this.page).toHaveTitle(/Prowler/);
    await expect(this.page).toHaveURL(/\/providers\/test-connection/);

    // Verify the Launch scan button is visible
    const launchScanButton = this.page
      .locator("button")
      .filter({ hasText: "Launch scan" });

    await expect(launchScanButton).toBeVisible();
  }

  async verifyLoadProviderPageAfterNewProvider(): Promise<void> {
    // Verify the provider page is loaded

    await expect(this.page).toHaveTitle(/Prowler/);
    await expect(this.providersTable).toBeVisible();
  }

  async verifySingleRowForProviderUID(providerUID: string): Promise<boolean> {
    // Verify if table has 1 row and that row contains providerUID

    await expect(this.providersTable).toBeVisible();

    // Get the matching rows
    const matchingRows = this.providersTable.locator("tbody tr", {
      hasText: providerUID,
    });

    // Verify the number of matching rows is 1
    const count = await matchingRows.count();

    if (count !== 1) return false;
    return true;
  }

  async deleteProviderIfExists(providerUID: string): Promise<void> {
    // Delete the provider if it exists

    // Navigate to providers page
    await this.goto();
    await expect(this.providersTable).toBeVisible({ timeout: 10000 });

    // Find and use the search input to filter the table
    const searchInput = this.page.getByPlaceholder(/search|filter/i);
    await expect(searchInput).toBeVisible({ timeout: 5000 });

    // Clear and search for the specific provider
    await searchInput.clear();
    await searchInput.fill(providerUID);
    await searchInput.press("Enter");

    // Additional wait for React table to re-render with the server-filtered data
    // The filtering happens on the server, but the table component needs time
    // to process the response and update the DOM after network idle
    await this.page.waitForTimeout(1500);

    // Get all rows from the table
    const allRows = this.providersTable.locator("tbody tr");

    // Helper function to check if a row is the "No results" row
    const isNoResultsRow = async (row: Locator): Promise<boolean> => {
      const text = await row.textContent();

      return text?.includes("No results") || text?.includes("No data") || false;
    };

    // Helper function to find the row with the specific UID
    const findProviderRow = async (): Promise<Locator | null> => {
      const count = await allRows.count();

      for (let i = 0; i < count; i++) {
        const row = allRows.nth(i);

        // Skip "No results" rows
        if (await isNoResultsRow(row)) {
          continue;
        }

        // Check if this row contains the UID in the UID column (column 3)
        const uidCell = row.locator("td").nth(3);
        const uidText = await uidCell.textContent();

        if (uidText?.includes(providerUID)) {
          return row;
        }
      }

      return null;
    };

    // Wait for filtering to complete (max 0 or 1 data rows)
    await expect(async () => {
      const targetRow = await findProviderRow();
      const count = await allRows.count();

      // Count only real data rows (not "No results")
      let dataRowCount = 0;
      for (let i = 0; i < count; i++) {
        if (!(await isNoResultsRow(allRows.nth(i)))) {
          dataRowCount++;
        }
      }

      // Should have 0 or 1 data row
      expect(dataRowCount).toBeLessThanOrEqual(1);
    }).toPass({ timeout: 20000 });

    // Find the provider row
    const targetRow = await findProviderRow();

    if (!targetRow) {
      // Provider not found, nothing to delete
      // Navigate back to providers page to ensure clean state
      await this.goto();
      await expect(this.providersTable).toBeVisible({ timeout: 10000 });
      return;
    }

    // Find and click the action button (last cell = actions column)
    const actionButton = targetRow.locator("td").last().locator("button").first();

    await expect(actionButton).toBeVisible({ timeout: 5000 });
    await actionButton.click();

    // Wait for dropdown menu to appear and find delete option
    const deleteMenuItem = this.page.getByRole("menuitem", {
      name: /delete.*provider/i,
    });

    await expect(deleteMenuItem).toBeVisible({ timeout: 5000 });
    await deleteMenuItem.click();

    // Wait for confirmation modal to appear
    const modal = this.page.locator('[role="dialog"], .modal, [data-testid*="modal"]').first();
    
    await expect(modal).toBeVisible({ timeout: 10000 });

    // Find and click the delete confirmation button
    await expect(this.deleteProviderConfirmationButton).toBeVisible({
      timeout: 5000,
    });
    await this.deleteProviderConfirmationButton.click();

    // Wait for modal to close (this indicates deletion was initiated)
    await expect(modal).not.toBeVisible({ timeout: 10000 });

    // Navigate back to providers page to ensure clean state
    await this.goto();
    await expect(this.providersTable).toBeVisible({ timeout: 10000 });
  }

  async selectAuthenticationMethod(method: AWSCredentialType): Promise<void> {
    // Select the authentication method

    // Search botton that contains text AWS SDK Default or Prowler Cloud will assume or Access & Secret Key
    const button = this.page.locator("button").filter({
      hasText: /AWS SDK Default|Prowler Cloud will assume|Access & Secret Key/i,
    });
    await button.click();

    if (method === AWS_CREDENTIAL_OPTIONS.AWS_ROLE_ARN) {
      const modal = this.page
        .locator('[role="dialog"], .modal, [data-testid*="modal"]')
        .first();
      await expect(modal).toBeVisible({ timeout: 10000 });

      // Select the role credentials
      this.page
        .getByRole("option", { name: "Access & Secret Key" })
        .click({ force: true });
    } else {
      throw new Error(`Invalid authentication method: ${method}`);
    }
  }
}
