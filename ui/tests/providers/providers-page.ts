import { Page, Locator, expect } from "@playwright/test";
import { BasePage } from "../base-page";

// AWS provider data
export interface AWSProviderData {
  accountId: string;
  alias?: string;
}

export interface AWSOrganizationsProviderData {
  organizationId: string;
  organizationName?: string;
}

export interface AWSOrganizationsProviderCredential {
  roleArn: string;
  stackSetDeployed?: boolean;
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

// GCP provider data
export interface GCPProviderData {
  projectId: string;
  alias?: string;
}

// GitHub provider data
export interface GitHubProviderData {
  username: string;
  alias?: string;
}

// OCI provider data
export interface OCIProviderData {
  tenancyId: string;
  alias?: string;
}

// AlibabaCloud provider data
export interface AlibabaCloudProviderData {
  accountId: string;
  alias?: string;
}

// AWS credential options
export const AWS_CREDENTIAL_OPTIONS = {
  AWS_ROLE_ARN: "role",
  AWS_CREDENTIALS: "credentials",
  AWS_SDK_DEFAULT: "aws-sdk-default",
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
  KUBECONFIG_CONTENT: "kubeconfig",
} as const;

// Kubernetes credential type
type KubernetesCredentialType =
  (typeof KUBERNETES_CREDENTIAL_OPTIONS)[keyof typeof KUBERNETES_CREDENTIAL_OPTIONS];

// Kubernetes provider credential
export interface KubernetesProviderCredential {
  type: KubernetesCredentialType;
  kubeconfigContent: string;
}

// GCP credential options
export const GCP_CREDENTIAL_OPTIONS = {
  GCP_SERVICE_ACCOUNT: "service_account",
} as const;

// GCP credential type
type GCPCredentialType =
  (typeof GCP_CREDENTIAL_OPTIONS)[keyof typeof GCP_CREDENTIAL_OPTIONS];

// GCP provider credential
export interface GCPProviderCredential {
  type: GCPCredentialType;
  serviceAccountKey: string;
}

// GitHub credential options
export const GITHUB_CREDENTIAL_OPTIONS = {
  GITHUB_PERSONAL_ACCESS_TOKEN: "personal_access_token",
  GITHUB_ORGANIZATION_ACCESS_TOKEN: "organization_access_token",
  GITHUB_APP: "github_app",
} as const;

// GitHub credential type
type GitHubCredentialType =
  (typeof GITHUB_CREDENTIAL_OPTIONS)[keyof typeof GITHUB_CREDENTIAL_OPTIONS];

// GitHub provider personal access token credential
export interface GitHubProviderCredential {
  type: GitHubCredentialType;
  personalAccessToken?: string;
  githubAppId?: string;
  githubAppPrivateKey?: string;
}

// OCI credential options
export const OCI_CREDENTIAL_OPTIONS = {
  OCI_API_KEY: "api_key",
} as const;

// OCI credential type
type OCICredentialType =
  (typeof OCI_CREDENTIAL_OPTIONS)[keyof typeof OCI_CREDENTIAL_OPTIONS];

// OCI provider credential
export interface OCIProviderCredential {
  type: OCICredentialType;
  tenancyId: string;
  userId?: string;
  fingerprint?: string;
  keyContent?: string;
  region?: string;
}

// AlibabaCloud credential options
export const ALIBABACLOUD_CREDENTIAL_OPTIONS = {
  ALIBABACLOUD_CREDENTIALS: "credentials",
  ALIBABACLOUD_ROLE: "role",
} as const;

// AlibabaCloud credential type
type AlibabaCloudCredentialType =
  (typeof ALIBABACLOUD_CREDENTIAL_OPTIONS)[keyof typeof ALIBABACLOUD_CREDENTIAL_OPTIONS];

// AlibabaCloud provider credential
export interface AlibabaCloudProviderCredential {
  type: AlibabaCloudCredentialType;
  accessKeyId: string;
  accessKeySecret: string;
  roleArn?: string;
  roleSessionName?: string;
}

// Providers page
export class ProvidersPage extends BasePage {
  readonly wizardModal: Locator;
  readonly wizardTitle: Locator;

  // Alias input
  readonly aliasInput: Locator;

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
  readonly ociProviderRadio: Locator;
  readonly alibabacloudProviderRadio: Locator;

  // AWS provider form elements
  readonly accountIdInput: Locator;
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

  // GitHub credentials type selection
  readonly githubPersonalAccessTokenRadio: Locator;
  readonly githubAppCredentialsRadio: Locator;

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

  // GCP provider form elements
  readonly gcpProjectIdInput: Locator;
  readonly gcpServiceAccountKeyInput: Locator;
  readonly gcpServiceAccountRadio: Locator;

  // GitHub provider form elements
  readonly githubUsernameInput: Locator;
  readonly githubAppIdInput: Locator;
  readonly githubAppPrivateKeyInput: Locator;
  readonly githubPersonalAccessTokenInput: Locator;

  // OCI provider form elements
  readonly ociTenancyIdInput: Locator;
  readonly ociUserIdInput: Locator;
  readonly ociFingerprintInput: Locator;
  readonly ociKeyContentInput: Locator;
  readonly ociRegionInput: Locator;

  // AlibabaCloud provider form elements
  readonly alibabacloudAccountIdInput: Locator;
  readonly alibabacloudAccessKeyIdInput: Locator;
  readonly alibabacloudAccessKeySecretInput: Locator;
  readonly alibabacloudRoleArnInput: Locator;
  readonly alibabacloudRoleSessionNameInput: Locator;
  readonly alibabacloudStaticCredentialsRadio: Locator;
  readonly alibabacloudRoleCredentialsRadio: Locator;

  // Delete button
  readonly deleteProviderConfirmationButton: Locator;

  constructor(page: Page) {
    super(page);

    this.wizardModal = page
      .getByRole("dialog")
      .filter({
        has: page.getByRole("heading", {
          name: /Adding A Cloud Provider|Update Provider Credentials/i,
        }),
      })
      .first();
    this.wizardTitle = page.getByRole("heading", {
      name: /Adding A Cloud Provider|Update Provider Credentials/i,
    });

    // Button to add a new cloud provider
    this.addProviderButton = page
      .getByRole("button", {
        name: "Add Cloud Provider",
        exact: true,
      })
      .or(
        page.getByRole("link", {
          name: "Add Cloud Provider",
          exact: true,
        }),
      );

    // Table displaying existing providers
    this.providersTable = page.getByRole("table");

    // Option buttons to select the type of cloud provider (listbox with options)
    this.awsProviderRadio = page.getByRole("option", {
      name: /Amazon Web Services/i,
    });
    // Google Cloud Platform
    this.gcpProviderRadio = page.getByRole("option", {
      name: /Google Cloud Platform/i,
    });
    // Microsoft Azure
    this.azureProviderRadio = page.getByRole("option", {
      name: /Microsoft Azure/i,
    });
    // Microsoft 365
    this.m365ProviderRadio = page.getByRole("option", {
      name: /Microsoft 365/i,
    });
    // Kubernetes
    this.kubernetesProviderRadio = page.getByRole("option", {
      name: /Kubernetes/i,
    });
    // GitHub
    this.githubProviderRadio = page.getByRole("option", {
      name: /GitHub/i,
    });
    // Oracle Cloud Infrastructure
    this.ociProviderRadio = page.getByRole("option", {
      name: /Oracle Cloud Infrastructure/i,
    });
    // Alibaba Cloud
    this.alibabacloudProviderRadio = page.getByRole("option", {
      name: /Alibaba Cloud/i,
    });

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
    this.m365CertificateContentInput = page.getByRole("textbox", {
      name: "Certificate Content",
    });

    // Kubernetes provider form inputs
    this.kubernetesContextInput = page.getByRole("textbox", {
      name: "Context",
    });
    this.kubernetesKubeconfigContentInput = page.getByRole("textbox", {
      name: "Kubeconfig Content",
    });

    // GCP provider form inputs
    this.gcpProjectIdInput = page.getByRole("textbox", { name: "Project ID" });
    this.gcpServiceAccountKeyInput = page.getByRole("textbox", {
      name: "Service Account Key",
    });

    // GitHub provider form inputs
    this.githubUsernameInput = page.getByRole("textbox", { name: "Username" });
    this.githubPersonalAccessTokenInput = page.getByRole("textbox", {
      name: "Personal Access Token",
    });
    this.githubAppIdInput = page.getByRole("textbox", {
      name: "GitHub App ID",
    });
    this.githubAppPrivateKeyInput = page.getByRole("textbox", {
      name: "GitHub App Private Key",
    });

    // OCI provider form inputs
    this.ociTenancyIdInput = page.getByRole("textbox", {
      name: /Tenancy OCID/i,
    });
    this.ociUserIdInput = page.getByRole("textbox", { name: /User OCID/i });
    this.ociFingerprintInput = page.getByRole("textbox", {
      name: /Fingerprint/i,
    });
    this.ociKeyContentInput = page.getByRole("textbox", {
      name: /Private Key Content/i,
    });
    this.ociRegionInput = page.getByRole("textbox", { name: /Region/i });

    // AlibabaCloud provider form inputs
    this.alibabacloudAccountIdInput = page.getByRole("textbox", {
      name: "Account ID",
    });
    this.alibabacloudAccessKeyIdInput = page.getByRole("textbox", {
      name: "Access Key ID",
    });
    this.alibabacloudAccessKeySecretInput = page.getByRole("textbox", {
      name: "Access Key Secret",
    });
    this.alibabacloudRoleArnInput = page.getByRole("textbox", {
      name: "Role ARN",
    });
    this.alibabacloudRoleSessionNameInput = page.getByRole("textbox", {
      name: "Role Session Name",
    });
    // Radios for selecting AlibabaCloud credentials method
    this.alibabacloudStaticCredentialsRadio = page.getByRole("radio", {
      name: /Connect via Access Keys/i,
    });
    this.alibabacloudRoleCredentialsRadio = page.getByRole("radio", {
      name: /Connect assuming RAM Role/i,
    });

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

    // Radios for selecting GCP credentials method
    this.gcpServiceAccountRadio = page.getByRole("radio", {
      name: /Service Account Key/i,
    });

    // Radios for selecting GitHub credentials method
    this.githubPersonalAccessTokenRadio = page.getByRole("radio", {
      name: /Personal Access Token/i,
    });
    this.githubAppCredentialsRadio = page.getByRole("radio", {
      name: /GitHub App/i,
    });

    // Inputs for IAM Role credentials
    this.roleArnInput = page.getByRole("textbox", { name: "Role ARN" });
    this.externalIdInput = page.getByRole("textbox", { name: "External ID" });

    // Inputs for static credentials (type="password" fields have no textbox role)
    this.accessKeyIdInput = page.getByLabel(/Access Key ID/i).first();
    this.secretAccessKeyInput = page.getByLabel(/Secret Access Key/i).first();

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

  async gotoFresh(): Promise<void> {
    // Go to the providers page with fresh navigation

    await super.gotoFresh("/providers");
  }

  private async verifyPageHasProwlerTitle(): Promise<void> {
    await expect(this.page).toHaveTitle(/Prowler/);
  }

  async clickAddProvider(): Promise<void> {
    // Click the add provider button

    await this.addProviderButton.click();
  }

  async openProviderWizardModal(): Promise<void> {
    await this.clickAddProvider();
    await this.verifyWizardModalOpen();
  }

  async closeProviderWizardModal(): Promise<void> {
    await this.page.keyboard.press("Escape");
    await expect(this.wizardModal).not.toBeVisible();
  }

  async verifyWizardModalOpen(): Promise<void> {
    await expect(this.wizardModal).toBeVisible();
    await expect(this.wizardTitle).toBeVisible();
  }

  async advanceWizardStep(): Promise<void> {
    await this.clickNext();
  }

  private async selectProviderRadio(radio: Locator): Promise<void> {
    // Force click to handle overlay intercepts
    await radio.click({ force: true });
  }

  async selectAWSProvider(): Promise<void> {
    await this.selectProviderRadio(this.awsProviderRadio);
  }

  async selectAZUREProvider(): Promise<void> {
    await this.selectProviderRadio(this.azureProviderRadio);
  }

  async selectM365Provider(): Promise<void> {
    await this.selectProviderRadio(this.m365ProviderRadio);
  }

  async selectKubernetesProvider(): Promise<void> {
    await this.selectProviderRadio(this.kubernetesProviderRadio);
  }

  async selectGCPProvider(): Promise<void> {
    await this.selectProviderRadio(this.gcpProviderRadio);
  }

  async selectGitHubProvider(): Promise<void> {
    await this.selectProviderRadio(this.githubProviderRadio);
  }

  async selectAWSSingleAccountMethod(): Promise<void> {
    const singleAccountOption = this.page.getByRole("radio", {
      name: "Add A Single AWS Cloud Account",
      exact: true,
    });
    await expect(singleAccountOption).toBeVisible({ timeout: 10000 });
    await singleAccountOption.click();
  }

  async selectAWSOrganizationsMethod(): Promise<void> {
    await this.page
      .getByRole("radio", {
        name: "Add Multiple Accounts With AWS Organizations",
        exact: true,
      })
      .click();
  }

  async verifyOrganizationsAuthenticationStepLoaded(): Promise<void> {
    await this.verifyWizardModalOpen();
    await expect(
      this.page.getByRole("heading", {
        name: /Authentication Details/i,
      }),
    ).toBeVisible();
  }

  async verifyOrganizationsAccountSelectionStepLoaded(): Promise<void> {
    await this.verifyWizardModalOpen();
    await expect(
      this.page.getByText(
        /Confirm all accounts under this Organization you want to add to Prowler\./i,
      ),
    ).toBeVisible();
  }

  async verifyOrganizationsLaunchStepLoaded(): Promise<void> {
    await this.verifyWizardModalOpen();
    await expect(this.page.getByText(/Accounts Connected!/i)).toBeVisible();
  }

  async chooseOrganizationsScanSchedule(
    option: "daily" | "single",
  ): Promise<void> {
    const trigger = this.page.getByRole("combobox");
    await trigger.click();

    const optionName =
      option === "single"
        ? "Run a single scan (no recurring schedule)"
        : "Scan Daily (every 24 hours)";

    await this.page.getByRole("option", { name: optionName }).click();
  }

  async fillAWSProviderDetails(data: AWSProviderData): Promise<void> {
    await this.selectAWSSingleAccountMethod();
    await expect(this.accountIdInput).toBeVisible({ timeout: 10000 });
    await this.accountIdInput.fill(data.accountId);

    if (data.alias) {
      await this.aliasInput.fill(data.alias);
    }
  }

  async fillAWSOrganizationsProviderDetails(
    data: AWSOrganizationsProviderData,
  ): Promise<void> {
    const organizationIdInput = this.page.getByRole("textbox", {
      name: "Organization ID",
      exact: true,
    });
    await expect(organizationIdInput).toBeVisible({ timeout: 10000 });
    await organizationIdInput.fill(data.organizationId.toLowerCase());

    if (data.organizationName) {
      await this.page
        .getByRole("textbox", { name: "Name (optional)", exact: true })
        .fill(data.organizationName);
    }
  }

  async fillAWSOrganizationsCredentials(
    credentials: AWSOrganizationsProviderCredential,
  ): Promise<void> {
    const roleArnInput = this.page.getByRole("textbox", {
      name: "Role ARN",
      exact: true,
    });
    await expect(roleArnInput).toBeVisible({ timeout: 10000 });
    await roleArnInput.fill(credentials.roleArn);

    if (credentials.stackSetDeployed ?? true) {
      const stackSetCheckbox = this.page.getByRole("checkbox", {
        name: /The StackSet has been successfully deployed in AWS/i,
      });
      if (!(await stackSetCheckbox.isChecked())) {
        await stackSetCheckbox.click();
      }
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

  async fillKubernetesProviderDetails(
    data: KubernetesProviderData,
  ): Promise<void> {
    // Fill the Kubernetes provider details

    await this.kubernetesContextInput.fill(data.context);

    if (data.alias) {
      await this.aliasInput.fill(data.alias);
    }
  }

  async fillGCPProviderDetails(data: GCPProviderData): Promise<void> {
    // Fill the GCP provider details

    await this.gcpProjectIdInput.fill(data.projectId);

    if (data.alias) {
      await this.aliasInput.fill(data.alias);
    }
  }

  async fillGitHubProviderDetails(data: GitHubProviderData): Promise<void> {
    // Fill the GitHub provider details

    await this.githubUsernameInput.fill(data.username);

    if (data.alias) {
      await this.aliasInput.fill(data.alias);
    }
  }

  async clickNext(): Promise<void> {
    await this.verifyWizardModalOpen();

    const actionNames = [
      "Go to scans",
      "Authenticate",
      "Next",
      "Save",
      "Check connection",
      "Launch scan",
    ] as const;

    for (const actionName of actionNames) {
      const button = this.page.getByRole("button", {
        name: actionName,
        exact: true,
      });
      if (await button.isVisible().catch(() => false)) {
        await button.click();
        if (actionName === "Check connection") {
          await this.handleCheckConnectionCompletion();
        }
        if (actionName === "Launch scan") {
          await this.handleLaunchScanCompletion();
        }
        return;
      }
    }

    throw new Error(
      "Could not find an actionable primary button in the provider wizard modal.",
    );
  }

  private async handleCheckConnectionCompletion(): Promise<void> {
    const launchScanButton = this.page.getByRole("button", {
      name: "Launch scan",
      exact: true,
    });
    const connectionError = this.page.locator(
      "div.border-border-error p.text-text-error-primary",
    );

    try {
      await Promise.race([
        launchScanButton.waitFor({ state: "visible", timeout: 30000 }),
        this.wizardModal.waitFor({ state: "hidden", timeout: 30000 }),
        connectionError.waitFor({ state: "visible", timeout: 30000 }),
      ]);
    } catch {
      // Continue and inspect visible state below.
    }

    if (await connectionError.isVisible().catch(() => false)) {
      const errorText = await connectionError.textContent();
      throw new Error(
        `Test connection failed with error: ${errorText?.trim() || "Unknown error"}`,
      );
    }

    if (await launchScanButton.isVisible().catch(() => false)) {
      await launchScanButton.click();
      await this.handleLaunchScanCompletion();
    }
  }

  private async handleLaunchScanCompletion(): Promise<void> {
    const connectionError = this.page.locator(
      "div.border-border-error p.text-text-error-primary",
    );
    const launchErrorToast = this.page.getByRole("alert").filter({
      hasText: /Unable to launch scan/i,
    });

    try {
      await Promise.race([
        this.wizardModal.waitFor({ state: "hidden", timeout: 30000 }),
        connectionError.waitFor({ state: "visible", timeout: 30000 }),
        launchErrorToast.waitFor({ state: "visible", timeout: 30000 }),
      ]);
    } catch {
      // Continue and inspect visible state below.
    }

    if (await connectionError.isVisible().catch(() => false)) {
      const errorText = await connectionError.textContent();
      throw new Error(
        `Test connection failed with error: ${errorText?.trim() || "Unknown error"}`,
      );
    }

    if (await launchErrorToast.isVisible().catch(() => false)) {
      const errorText = await launchErrorToast.textContent();
      throw new Error(
        `Launch scan failed with error: ${errorText?.trim() || "Unknown error"}`,
      );
    }

    await expect(this.wizardModal).not.toBeVisible({ timeout: 30000 });
    await this.page.waitForURL(/\/providers/, { timeout: 30000 });
    await expect(this.providersTable).toBeVisible({ timeout: 30000 });
  }

  async selectCredentialsType(type: AWSCredentialType): Promise<void> {
    await this.verifyWizardModalOpen();
    await expect(this.roleCredentialsRadio).toBeVisible();

    if (type === AWS_CREDENTIAL_OPTIONS.AWS_ROLE_ARN) {
      await this.roleCredentialsRadio.click({ force: true });
    } else if (type === AWS_CREDENTIAL_OPTIONS.AWS_CREDENTIALS) {
      await this.staticCredentialsRadio.click({ force: true });
    } else {
      throw new Error(`Invalid AWS credential type: ${type}`);
    }
  }

  async selectM365CredentialsType(type: M365CredentialType): Promise<void> {
    await this.verifyWizardModalOpen();
    await expect(this.m365StaticCredentialsRadio).toBeVisible();

    if (type === M365_CREDENTIAL_OPTIONS.M365_CREDENTIALS) {
      await this.m365StaticCredentialsRadio.click({ force: true });
    } else if (type === M365_CREDENTIAL_OPTIONS.M365_CERTIFICATE_CREDENTIALS) {
      await this.m365CertificateCredentialsRadio.click({ force: true });
    } else {
      throw new Error(`Invalid M365 credential type: ${type}`);
    }
  }

  async selectGCPCredentialsType(type: GCPCredentialType): Promise<void> {
    await this.verifyWizardModalOpen();
    await expect(this.gcpServiceAccountRadio).toBeVisible();
    if (type === GCP_CREDENTIAL_OPTIONS.GCP_SERVICE_ACCOUNT) {
      await this.gcpServiceAccountRadio.click({ force: true });
    } else {
      throw new Error(`Invalid GCP credential type: ${type}`);
    }
  }

  async selectGitHubCredentialsType(type: GitHubCredentialType): Promise<void> {
    await this.verifyWizardModalOpen();
    await expect(this.githubPersonalAccessTokenRadio).toBeVisible();

    if (type === GITHUB_CREDENTIAL_OPTIONS.GITHUB_PERSONAL_ACCESS_TOKEN) {
      await this.githubPersonalAccessTokenRadio.click({ force: true });
    } else if (type === GITHUB_CREDENTIAL_OPTIONS.GITHUB_APP) {
      await this.githubAppCredentialsRadio.click({ force: true });
    } else {
      throw new Error(`Invalid GitHub credential type: ${type}`);
    }
  }

  async fillRoleCredentials(credentials: AWSProviderCredential): Promise<void> {
    await expect(this.roleArnInput).toBeVisible({ timeout: 10000 });
    const accessKeyInputInWizard = this.wizardModal.getByPlaceholder(
      "Enter the AWS Access Key ID",
    );
    const secretKeyInputInWizard = this.wizardModal.getByPlaceholder(
      "Enter the AWS Secret Access Key",
    );
    const accessKeyId =
      credentials.accessKeyId || process.env.E2E_AWS_PROVIDER_ACCESS_KEY;
    const secretAccessKey =
      credentials.secretAccessKey || process.env.E2E_AWS_PROVIDER_SECRET_KEY;

    const shouldFillStaticKeys = Boolean(
      accessKeyId || secretAccessKey,
    );
    if (shouldFillStaticKeys) {
      const accessKeyIsVisible = await accessKeyInputInWizard
        .isVisible()
        .catch(() => false);

      // In cloud env the default can be SDK mode, so expose Access/Secret explicitly.
      if (!accessKeyIsVisible) {
        await this.selectAuthenticationMethod(
          AWS_CREDENTIAL_OPTIONS.AWS_ROLE_ARN,
        );
      }
    }

    if (accessKeyId) {
      await expect(accessKeyInputInWizard).toBeVisible({ timeout: 10000 });
      await accessKeyInputInWizard.fill(accessKeyId);
      await expect(accessKeyInputInWizard).toHaveValue(accessKeyId);
    }
    if (secretAccessKey) {
      await expect(secretKeyInputInWizard).toBeVisible({ timeout: 10000 });
      await secretKeyInputInWizard.fill(secretAccessKey);
      await expect(secretKeyInputInWizard).toHaveValue(secretAccessKey);
    }
    if (credentials.roleArn) {
      await this.roleArnInput.fill(credentials.roleArn);
    }
    if (credentials.externalId) {
      if (await this.externalIdInput.isEnabled()) {
        await this.externalIdInput.fill(credentials.externalId);
      }
    }
  }

  async fillStaticCredentials(
    credentials: AWSProviderCredential,
  ): Promise<void> {
    const accessKeyInputInWizard = this.wizardModal.getByPlaceholder(
      "Enter the AWS Access Key ID",
    );
    const secretKeyInputInWizard = this.wizardModal.getByPlaceholder(
      "Enter the AWS Secret Access Key",
    );
    const accessKeyId =
      credentials.accessKeyId || process.env.E2E_AWS_PROVIDER_ACCESS_KEY;
    const secretAccessKey =
      credentials.secretAccessKey || process.env.E2E_AWS_PROVIDER_SECRET_KEY;

    if (accessKeyId) {
      await expect(accessKeyInputInWizard).toBeVisible({ timeout: 10000 });
      await accessKeyInputInWizard.fill(accessKeyId);
      await expect(accessKeyInputInWizard).toHaveValue(accessKeyId);
    }
    if (secretAccessKey) {
      await expect(secretKeyInputInWizard).toBeVisible({ timeout: 10000 });
      await secretKeyInputInWizard.fill(secretAccessKey);
      await expect(secretKeyInputInWizard).toHaveValue(secretAccessKey);
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

  async fillKubernetesCredentials(
    credentials: KubernetesProviderCredential,
  ): Promise<void> {
    // Fill the Kubernetes credentials form

    if (credentials.kubeconfigContent) {
      await this.kubernetesKubeconfigContentInput.fill(
        credentials.kubeconfigContent,
      );
    }
  }

  async fillGCPServiceAccountKeyCredentials(
    credentials: GCPProviderCredential,
  ): Promise<void> {
    // Fill the GCP credentials form

    if (credentials.serviceAccountKey) {
      await this.gcpServiceAccountKeyInput.fill(credentials.serviceAccountKey);
    }
  }

  async fillGitHubPersonalAccessTokenCredentials(
    credentials: GitHubProviderCredential,
  ): Promise<void> {
    // Fill the GitHub personal access token credentials form

    if (credentials.personalAccessToken) {
      await this.githubPersonalAccessTokenInput.fill(
        credentials.personalAccessToken,
      );
    }
  }

  async fillGitHubAppCredentials(
    credentials: GitHubProviderCredential,
  ): Promise<void> {
    // Fill the GitHub app credentials form

    if (credentials.githubAppId) {
      await this.githubAppIdInput.fill(credentials.githubAppId);
    }
    if (credentials.githubAppPrivateKey) {
      await this.githubAppPrivateKeyInput.fill(credentials.githubAppPrivateKey);
    }
  }

  async selectOCIProvider(): Promise<void> {
    await this.selectProviderRadio(this.ociProviderRadio);
  }

  async fillOCIProviderDetails(data: OCIProviderData): Promise<void> {
    // Fill the OCI provider details

    await this.ociTenancyIdInput.fill(data.tenancyId);

    if (data.alias) {
      await this.aliasInput.fill(data.alias);
    }
  }

  async fillOCICredentials(credentials: OCIProviderCredential): Promise<void> {
    // Fill the OCI credentials form

    if (credentials.userId) {
      await this.ociUserIdInput.fill(credentials.userId);
    }
    if (credentials.fingerprint) {
      await this.ociFingerprintInput.fill(credentials.fingerprint);
    }
    if (credentials.keyContent) {
      await this.ociKeyContentInput.fill(credentials.keyContent);
    }
    if (credentials.region) {
      await this.ociRegionInput.fill(credentials.region);
    }
  }

  async verifyOCICredentialsPageLoaded(): Promise<void> {
    // Verify the OCI credentials page is loaded (add flow - all fields visible)

    await this.verifyPageHasProwlerTitle();
    await expect(this.ociTenancyIdInput).toBeVisible();
    await expect(this.ociUserIdInput).toBeVisible();
    await expect(this.ociFingerprintInput).toBeVisible();
    await expect(this.ociKeyContentInput).toBeVisible();
    await expect(this.ociRegionInput).toBeVisible();
  }

  async verifyOCIUpdateCredentialsPageLoaded(): Promise<void> {
    // Verify the OCI update credentials page is loaded
    // Note: Tenancy OCID is hidden in update flow (auto-populated from provider UID)

    await this.verifyPageHasProwlerTitle();
    await expect(this.ociUserIdInput).toBeVisible();
    await expect(this.ociFingerprintInput).toBeVisible();
    await expect(this.ociKeyContentInput).toBeVisible();
    await expect(this.ociRegionInput).toBeVisible();
  }

  async selectAlibabaCloudProvider(): Promise<void> {
    await this.selectProviderRadio(this.alibabacloudProviderRadio);
  }

  async fillAlibabaCloudProviderDetails(
    data: AlibabaCloudProviderData,
  ): Promise<void> {
    // Fill the AlibabaCloud provider details

    await this.alibabacloudAccountIdInput.fill(data.accountId);

    if (data.alias) {
      await this.aliasInput.fill(data.alias);
    }
  }

  async selectAlibabaCloudCredentialsType(
    type: AlibabaCloudCredentialType,
  ): Promise<void> {
    await this.verifyWizardModalOpen();
    await expect(this.alibabacloudStaticCredentialsRadio).toBeVisible();

    if (type === ALIBABACLOUD_CREDENTIAL_OPTIONS.ALIBABACLOUD_CREDENTIALS) {
      await this.alibabacloudStaticCredentialsRadio.click({ force: true });
    } else if (type === ALIBABACLOUD_CREDENTIAL_OPTIONS.ALIBABACLOUD_ROLE) {
      await this.alibabacloudRoleCredentialsRadio.click({ force: true });
    } else {
      throw new Error(`Invalid AlibabaCloud credential type: ${type}`);
    }
  }

  async fillAlibabaCloudStaticCredentials(
    credentials: AlibabaCloudProviderCredential,
  ): Promise<void> {
    // Fill the AlibabaCloud static credentials form

    if (credentials.accessKeyId) {
      await this.alibabacloudAccessKeyIdInput.fill(credentials.accessKeyId);
    }
    if (credentials.accessKeySecret) {
      await this.alibabacloudAccessKeySecretInput.fill(
        credentials.accessKeySecret,
      );
    }
  }

  async fillAlibabaCloudRoleCredentials(
    credentials: AlibabaCloudProviderCredential,
  ): Promise<void> {
    // Fill the AlibabaCloud RAM Role credentials form

    if (credentials.roleArn) {
      await this.alibabacloudRoleArnInput.fill(credentials.roleArn);
    }
    if (credentials.accessKeyId) {
      await this.alibabacloudAccessKeyIdInput.fill(credentials.accessKeyId);
    }
    if (credentials.accessKeySecret) {
      await this.alibabacloudAccessKeySecretInput.fill(
        credentials.accessKeySecret,
      );
    }
    if (credentials.roleSessionName) {
      await this.alibabacloudRoleSessionNameInput.fill(
        credentials.roleSessionName,
      );
    }
  }

  async verifyAlibabaCloudCredentialsPageLoaded(): Promise<void> {
    // Verify the AlibabaCloud credentials page is loaded

    await this.verifyPageHasProwlerTitle();
    await expect(this.alibabacloudStaticCredentialsRadio).toBeVisible();
    await expect(this.alibabacloudRoleCredentialsRadio).toBeVisible();
  }

  async verifyAlibabaCloudStaticCredentialsPageLoaded(): Promise<void> {
    // Verify the AlibabaCloud static credentials page is loaded

    await this.verifyPageHasProwlerTitle();
    await expect(this.alibabacloudAccessKeyIdInput).toBeVisible();
    await expect(this.alibabacloudAccessKeySecretInput).toBeVisible();
  }

  async verifyAlibabaCloudRoleCredentialsPageLoaded(): Promise<void> {
    // Verify the AlibabaCloud RAM Role credentials page is loaded

    await this.verifyPageHasProwlerTitle();
    await expect(this.alibabacloudRoleArnInput).toBeVisible();
    await expect(this.alibabacloudAccessKeyIdInput).toBeVisible();
    await expect(this.alibabacloudAccessKeySecretInput).toBeVisible();
  }

  async verifyPageLoaded(): Promise<void> {
    // Verify the providers page is loaded

    await this.verifyPageHasProwlerTitle();
    await expect(this.addProviderButton).toBeVisible();
  }

  async verifyConnectAccountPageLoaded(): Promise<void> {
    // Verify the connect account page is loaded

    await this.verifyPageHasProwlerTitle();
    await this.verifyWizardModalOpen();
    await expect(this.awsProviderRadio).toBeVisible();
    await expect(this.ociProviderRadio).toBeVisible();
    await expect(this.gcpProviderRadio).toBeVisible();
    await expect(this.azureProviderRadio).toBeVisible();
    await expect(this.m365ProviderRadio).toBeVisible();
    await expect(this.kubernetesProviderRadio).toBeVisible();
    await expect(this.githubProviderRadio).toBeVisible();
    await expect(this.alibabacloudProviderRadio).toBeVisible();
  }

  async verifyCredentialsPageLoaded(): Promise<void> {
    await this.verifyPageHasProwlerTitle();
    await this.verifyWizardModalOpen();

    const selectorRadio = this.wizardModal.getByRole("radio", {
      name: /Connect assuming IAM Role/i,
    });
    const selectorHint = this.wizardModal.getByText(/Using IAM Role/i);
    const roleArnInForm = this.wizardModal.getByRole("textbox", {
      name: "Role ARN",
    });

    await Promise.race([
      selectorRadio.waitFor({ state: "visible", timeout: 20000 }),
      selectorHint.waitFor({ state: "visible", timeout: 20000 }),
      roleArnInForm.waitFor({ state: "visible", timeout: 20000 }),
    ]);
  }

  async verifyM365CredentialsPageLoaded(): Promise<void> {
    // Verify the M365 credentials page is loaded

    await this.verifyPageHasProwlerTitle();
    await expect(this.m365ClientIdInput).toBeVisible();
    await expect(this.m365ClientSecretInput).toBeVisible();
    await expect(this.m365TenantIdInput).toBeVisible();
  }

  async verifyM365CertificateCredentialsPageLoaded(): Promise<void> {
    // Verify the M365 certificate credentials page is loaded

    await this.verifyPageHasProwlerTitle();
    await expect(this.m365ClientIdInput).toBeVisible();
    await expect(this.m365TenantIdInput).toBeVisible();
    await expect(this.m365CertificateContentInput).toBeVisible();
  }

  async verifyKubernetesCredentialsPageLoaded(): Promise<void> {
    // Verify the Kubernetes credentials page is loaded

    await this.verifyPageHasProwlerTitle();
    await expect(this.kubernetesContextInput).toBeVisible();
  }

  async verifyGCPServiceAccountPageLoaded(): Promise<void> {
    // Verify the GCP service account page is loaded

    await this.verifyPageHasProwlerTitle();
    await expect(this.gcpServiceAccountKeyInput).toBeVisible();
  }

  async verifyGitHubPersonalAccessTokenPageLoaded(): Promise<void> {
    // Verify the GitHub personal access token page is loaded

    await this.verifyPageHasProwlerTitle();
    await expect(this.githubPersonalAccessTokenInput).toBeVisible();
  }

  async verifyGitHubAppPageLoaded(): Promise<void> {
    // Verify the GitHub app page is loaded

    await this.verifyPageHasProwlerTitle();
    await expect(this.githubAppIdInput).toBeVisible();
    await expect(this.githubAppPrivateKeyInput).toBeVisible();
  }

  async verifyLaunchScanPageLoaded(): Promise<void> {
    // Verify the launch scan page is loaded

    await this.verifyPageHasProwlerTitle();
    await this.verifyWizardModalOpen();

    // Some providers show "Check connection" before "Launch scan".
    const launchAction = this.page
      .getByRole("button", { name: "Launch scan", exact: true })
      .or(
        this.page.getByRole("button", {
          name: "Check connection",
          exact: true,
        }),
      );

    await expect(launchAction).toBeVisible();
  }

  async verifyLoadProviderPageAfterNewProvider(): Promise<void> {
    // Verify the provider page is loaded

    await this.verifyPageHasProwlerTitle();
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

  async selectAuthenticationMethod(method: AWSCredentialType): Promise<void> {
    // Select the authentication method (shadcn Select renders as combobox + listbox)

    const trigger = this.page.locator('[role="combobox"]').filter({
      hasText: /AWS SDK Default|Prowler Cloud will assume|Access & Secret Key/i,
    });

    await trigger.click();

    const listbox = this.page.getByRole("listbox");
    await expect(listbox).toBeVisible({ timeout: 10000 });

    if (method === AWS_CREDENTIAL_OPTIONS.AWS_ROLE_ARN) {
      await this.page
        .getByRole("option", { name: "Access & Secret Key" })
        .click({ force: true });
    } else if (method === AWS_CREDENTIAL_OPTIONS.AWS_SDK_DEFAULT) {
      await this.page
        .getByRole("option", {
          name: /AWS SDK Default|Prowler Cloud will assume your IAM role/i,
        })
        .click({ force: true });
    } else {
      throw new Error(`Invalid authentication method: ${method}`);
    }
  }

  async clickProviderRowActions(providerUid: string): Promise<void> {
    // Click the actions dropdown for a specific provider row
    const row = this.providersTable.locator("tbody tr", {
      hasText: providerUid,
    });
    await expect(row).toBeVisible();

    // Click the dropdown trigger - it's the last button in the row (after the copy button)
    const actionsButton = row.locator("button").last();
    await actionsButton.click();
  }

  async clickUpdateCredentials(providerUid: string): Promise<void> {
    // Click update credentials for a specific provider
    await this.clickProviderRowActions(providerUid);

    // Wait for dropdown menu to stabilize and click Update Credentials
    const updateCredentialsOption = this.page.getByRole("menuitem", {
      name: /Update Credentials/i,
    });
    await expect(updateCredentialsOption).toBeVisible();
    // Wait a bit for the menu to stabilize before clicking
    await this.page.waitForTimeout(100);
    await updateCredentialsOption.click({ force: true });
  }

  async verifyUpdateCredentialsPageLoaded(): Promise<void> {
    // Verify the update credentials page is loaded
    await this.verifyPageHasProwlerTitle();
    await this.verifyWizardModalOpen();
    await expect(
      this.page.getByRole("button", { name: "Authenticate", exact: true }),
    ).toBeVisible();
  }

  async verifyTestConnectionPageLoaded(): Promise<void> {
    await this.verifyPageHasProwlerTitle();
    const testConnectionAction = this.page
      .getByRole("button", { name: "Launch scan", exact: true })
      .or(
        this.page.getByRole("button", {
          name: "Check connection",
          exact: true,
        }),
      );

    // Some update flows return directly to providers list after authenticating.
    try {
      await Promise.race([
        testConnectionAction.waitFor({ state: "visible", timeout: 20000 }),
        this.providersTable.waitFor({ state: "visible", timeout: 20000 }),
      ]);
    } catch {
      // Fall through to explicit assertions below.
    }

    if (await this.providersTable.isVisible().catch(() => false)) {
      return;
    }

    await expect(testConnectionAction).toBeVisible();
  }
}
