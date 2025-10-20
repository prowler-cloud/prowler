import { Page, Locator, expect } from "@playwright/test";
import { BasePage } from "../base-page";

// AWS provider data
export interface AWSProviderData {
  accountId: string;
  alias?: string;
}

// AZURE provider data
export interface AZUREProviderData {
  subscriptionId: string;
  alias?: string;
}

// AWS credential options
export const AWS_CREDENTIAL_OPTIONS = {
  AWS_ROLE_ARN: "role",
  AWS_CREDENTIALS: "credentials"
} as const;

// AWS credential type
type AWSCredentialType = (typeof AWS_CREDENTIAL_OPTIONS)[keyof typeof AWS_CREDENTIAL_OPTIONS];

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
  AZURE_CREDENTIALS: "credentials"
} as const;

// AZURE credential type
type AZURECredentialType = (typeof AZURE_CREDENTIAL_OPTIONS)[keyof typeof AZURE_CREDENTIAL_OPTIONS];

// AZURE provider credential
export interface AZUREProviderCredential {
  type: AZURECredentialType;
  clientId:string;
  clientSecret:string;
  tenantId:string;
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

  // AWS role credentials form
  readonly roleArnInput: Locator;
  readonly externalIdInput: Locator;

  // AWS static credentials form
  readonly accessKeyIdInput: Locator;
  readonly secretAccessKeyInput: Locator;

  // AZURE provider form elements
  readonly subscriptionIdInput: Locator;
  readonly clientIdInput: Locator;
  readonly clientSecretInput: Locator;
  readonly tenantIdInput: Locator;

  // Delete button
  readonly deleteProviderConfirmationButton: Locator;

  constructor(page: Page) {
    super(page);

    // Button to add a new cloud provider
    this.addProviderButton = page.getByText("Add Cloud Provider", {
      exact: true,
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
    this.accountIdInput = page.getByLabel("Account ID");
    
    // AZURE provider form inputs
    this.subscriptionIdInput = page.getByLabel("Subscription ID");
    this.clientIdInput = page.getByLabel("Client ID");
    this.clientSecretInput = page.getByLabel("Client Secret");
    this.tenantIdInput = page.getByLabel("Tenant ID");
    
    // Alias input
    this.aliasInput = page.getByLabel("Provider alias (optional)");

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

    // Inputs for IAM Role credentials
    this.roleArnInput = page.getByLabel("Role ARN");
    this.externalIdInput = page.getByLabel("External ID");

    // Inputs for static credentials
    this.accessKeyIdInput = page.getByLabel("Access Key ID");
    this.secretAccessKeyInput = page.getByLabel("Secret Access Key");

    // Delete button
    this.deleteProviderConfirmationButton = page.locator(
      'button[aria-label="Delete"]',
    );
  }

  async goto(): Promise<void> {
    // Go to the providers page

    await super.goto("/providers");
  }

  async clickAddProvider(): Promise<void> {
    // Click the add provider button

    await this.addProviderButton.click();
    await this.waitForPageLoad();
  }

  async selectAWSProvider(): Promise<void> {
    
    // Prefer label-based click for radios, force if overlay intercepts
    await this.awsProviderRadio.click({ force: true });
    await this.waitForPageLoad();
  }

  async selectAZUREProvider(): Promise<void> {
    
    // Prefer label-based click for radios, force if overlay intercepts
    await this.azureProviderRadio.click({ force: true });
    await this.waitForPageLoad();
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

    await this.subscriptionIdInput.fill(data.subscriptionId);

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
      await this.waitForPageLoad();
      return;
    }

    // If on the "add-credentials" step, check for "Save" and "Next" buttons
    if (/\/providers\/add-credentials/.test(url)) {
      // Some UI implementations use "Save" instead of "Next" for primary action
      const saveBtn = this.saveButton;
      if (await saveBtn.count()) {
        await saveBtn.click();
        await this.waitForPageLoad();
        return;
      }
      // If "Save" is not present, try clicking the "Next" button
      if (await this.nextButton.count()) {
        await this.nextButton.click();
        await this.waitForPageLoad();
        return;
      }
    }

    // If on the "test-connection" step, click the "Launch scan" button
    if (/\/providers\/test-connection/.test(url)) {
      const buttonByText = this.page
        .locator("button")
        .filter({ hasText: "Launch scan" });

      await buttonByText.click();
      await this.waitForPageLoad();
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
        await this.waitForPageLoad();
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
    // Wait for the page to load
    await this.waitForPageLoad();
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

  async fillStaticCredentials(credentials: AWSProviderCredential): Promise<void> {
    // Fill the static credentials form

    if (credentials.accessKeyId) {
      await this.accessKeyIdInput.fill(credentials.accessKeyId);
    }
    if (credentials.secretAccessKey) {
      await this.secretAccessKeyInput.fill(credentials.secretAccessKey);
    }
  }

  async fillAZURECredentials(credentials: AZUREProviderCredential): Promise<void> {
    // Fill the azure credentials form

    if (credentials.clientId) {
      await this.clientIdInput.fill(credentials.clientId);
    }
    if (credentials.clientSecret) {
      await this.clientSecretInput.fill(credentials.clientSecret);
    }
    if (credentials.tenantId) {
      await this.tenantIdInput.fill(credentials.tenantId);
    }
  }


  async verifyPageLoaded(): Promise<void> {
    // Verify the providers page is loaded

    await expect(this.page).toHaveTitle(/Prowler/);
    await expect(this.addProviderButton).toBeVisible();
    await this.page.waitForLoadState('networkidle');
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

  async verifyProviderExists(providerUID: string): Promise<boolean> {
    // Filter search by providerUID

    await this.filterProvidersByProviderUID(providerUID);
    // Verify if table has 1 row
    if (!(await this.verifySingleRowForProviderUID(providerUID))) {
      return false;
    }
    return true;
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

  async filterProvidersByProviderUID(providerUID: string): Promise<void> {
    // Filter providers by providerUID

    // Go to the providers page
    await this.goto();

    // Verify the providers table is visible
    await expect(this.providersTable).toBeVisible();

    // Get the search input
    const searchInput = this.page.getByPlaceholder(/search|filter/i);
    if (!searchInput) {
      throw new Error("No search input available");
    }

    // Clear existing content and type the providerUID
    await searchInput.fill("");
    await searchInput.type(providerUID, { delay: 20 });

    // Try to submit the filter if the input acts on Enter
    try {
      await searchInput.press("Enter");
    } catch (error) {
      // Enter press might not be needed for all UIs
    }

    // Wait for table to update
    await this.waitForPageLoad();
  }

  async actionDeleteProvider(providerUID: string): Promise<void> {
    // Delete the provider

    // Filter search by providerUID
    await this.filterProvidersByProviderUID(providerUID);

    // Verify the providers table is visible
    await expect(this.providersTable).toBeVisible();

    // Find the first row in the filtered results
    const firstRow = this.providersTable.locator("tbody tr").first();

    // Verify the first row is visible
    await expect(firstRow).toBeVisible();

    // Get button in the last cell
    const lastCell = firstRow.locator("td").last();
    const actionButton = lastCell.locator("button").first();

    // Verify the action button is visible
    await actionButton.click();

    // Wait for the dropdown menu to appear
    await this.page.waitForSelector('[role="menu"], [role="menuitem"]', {
      timeout: 5000,
    });

    // Find the delete menu item
    const deleteMenuItem = this.page.getByRole("menuitem", {
      name: /delete.*provider/i,
    });

    // Verify the delete menu item is visible
    await expect(deleteMenuItem).toBeVisible();

    // Click the delete menu item with force to handle unstable elements
    await deleteMenuItem.click({ force: true });

    // Wait for the delete confirmation modal to appear
    await this.page.waitForSelector(
      '[role="dialog"], .modal, [data-testid*="modal"]',
      { timeout: 10000 },
    );

    // Find the delete confirmation button with multiple approaches
    let deleteButton = this.deleteProviderConfirmationButton;

    await expect(deleteButton).toBeVisible();

    // Click the delete button with force to handle unstable elements
    await deleteButton.click({ force: true });

    // Wait for the modal to disappear and the page to update
    const modalToCheck = this.page
      .locator('[role="dialog"], .modal, [data-testid*="modal"]')
      .first();

    // Verify the modal is not visible
    await expect(modalToCheck).not.toBeVisible();
    await this.waitForPageLoad();
  }
}
