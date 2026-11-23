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

// Google Workspace provider data
export interface GoogleWorkspaceProviderData {
  customerId: string;
  alias?: string;
}

// Google Workspace credential options
export const GOOGLEWORKSPACE_CREDENTIAL_OPTIONS = {
  GOOGLEWORKSPACE_SERVICE_ACCOUNT: "service_account",
} as const;

// Google Workspace credential type
type GoogleWorkspaceCredentialType =
  (typeof GOOGLEWORKSPACE_CREDENTIAL_OPTIONS)[keyof typeof GOOGLEWORKSPACE_CREDENTIAL_OPTIONS];

// Google Workspace provider credential
export interface GoogleWorkspaceProviderCredential {
  type: GoogleWorkspaceCredentialType;
  serviceAccountJson: string;
  delegatedUser: string;
}

// Okta provider data
export interface OktaProviderData {
  orgDomain: string;
  alias?: string;
}

// Okta credential options
export const OKTA_CREDENTIAL_OPTIONS = {
  OKTA_PRIVATE_KEY_JWT: "private_key_jwt",
} as const;

// Okta credential type
type OktaCredentialType =
  (typeof OKTA_CREDENTIAL_OPTIONS)[keyof typeof OKTA_CREDENTIAL_OPTIONS];

// Okta provider credential (OAuth 2.0 Private Key JWT)
export interface OktaProviderCredential {
  type: OktaCredentialType;
  clientId: string;
  privateKey: string;
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
  homeRegion?: string;
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

// Vercel provider data
export interface VercelProviderData {
  teamId: string;
  alias?: string;
}

// Vercel credential options
export const VERCEL_CREDENTIAL_OPTIONS = {
  VERCEL_API_TOKEN: "api_token",
} as const;

// Vercel credential type
type VercelCredentialType =
  (typeof VERCEL_CREDENTIAL_OPTIONS)[keyof typeof VERCEL_CREDENTIAL_OPTIONS];

// Vercel provider credential
export interface VercelProviderCredential {
  type: VercelCredentialType;
  apiToken: string;
}

// The wizard's final action. Setup pre-ticks "launch an initial scan", so the
// schedule step reads "Save and launch scan" ("Save" once unticked); manual-only
// accounts get "Launch scan" instead. Anchored so "Save" never matches a longer label.
const LAUNCH_STEP_ACTION_NAME = /^(Save|Save and launch scan|Launch scan)$/;

// The connect step's single submit: it saves the account and its credentials
// and tests the connection. The label names what each provider connects
// ("Connect account", "Connect subscription", ...), "Save and test" when the
// wizard was opened on an existing account, and "Retry connection" /
// "Check again" after a failed or still-pending test.
const CONNECT_STEP_SUBMIT_NAME =
  /^(Connect (account|subscription|project|cluster|tenant|repository|registry|tenancy|organization|workspace|team|provider)|Save and test|Retry connection|Check again)$/;

// Shown on the submit while the account is saved and its connection tested.
const CONNECT_STEP_BUSY_NAME = /^(Connecting\.\.\.|Testing connection\.\.\.)$/;

// Providers page
export class ProvidersPage extends BasePage {
  readonly wizardModal: Locator;
  readonly wizardTitle: Locator;

  // Alias input
  readonly aliasInput: Locator;

  // Button to add a new provider
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
  readonly googleworkspaceProviderRadio: Locator;
  readonly oktaProviderRadio: Locator;

  // Google Workspace provider form elements
  readonly googleworkspaceCustomerIdInput: Locator;
  readonly googleworkspaceServiceAccountJsonInput: Locator;
  readonly googleworkspaceDelegatedUserInput: Locator;

  // Okta provider form elements
  readonly oktaOrgDomainInput: Locator;
  readonly oktaClientIdInput: Locator;
  readonly oktaPrivateKeyInput: Locator;

  // Vercel provider form elements
  readonly vercelProviderRadio: Locator;
  readonly vercelTeamIdInput: Locator;
  readonly vercelApiTokenInput: Locator;

  // AWS provider form elements
  readonly accountIdInput: Locator;
  // Single submit of the connect step (account + credentials + connection test)
  readonly connectSubmitButton: Locator;
  // Inline connection-test failure on the connect step
  readonly connectionError: Locator;
  readonly backButton: Locator;
  readonly saveButton: Locator;
  readonly launchScanButton: Locator;

  // AWS connection method cards
  readonly roleCredentialsRadio: Locator;
  readonly staticCredentialsRadio: Locator;

  // M365 connection method cards
  readonly m365StaticCredentialsRadio: Locator;
  readonly m365CertificateCredentialsRadio: Locator;

  // GitHub connection method cards
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
  readonly ociHomeRegionCombobox: Locator;

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
          name: /Adding A Provider|Update Provider Credentials/i,
        }),
      })
      .first();
    this.wizardTitle = page.getByRole("heading", {
      name: /Adding A Provider|Update Provider Credentials/i,
    });

    // Button to add a new provider. When providers exist this is the filter-bar
    // "Add Provider" control; with zero providers the page renders the empty
    // state whose CTA is labelled "Open Add Provider modal" (button on
    // /providers, link on /scans). Only one of these is ever in the DOM at once.
    // Scoped to <main>: an empty tenant also gets an "Add Provider" CTA in the sidebar.
    const main = page.getByRole("main");
    this.addProviderButton = main
      .getByRole("button", {
        name: "Add Provider",
        exact: true,
      })
      .or(
        main.getByRole("link", {
          name: "Add Provider",
          exact: true,
        }),
      )
      .or(main.getByRole("button", { name: "Open Add Provider modal" }))
      .or(main.getByRole("link", { name: "Open Add Provider modal" }));

    // Table displaying existing providers
    this.providersTable = page.getByRole("table");

    // Option buttons to select the type of provider (listbox with options)
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
      name: "Kubernetes Context",
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
    this.githubUsernameInput = page.getByRole("textbox", {
      name: "Username/Organization",
    });
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
    this.ociHomeRegionCombobox = page.getByRole("combobox", {
      name: /Home Region/i,
    });

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
    // Connection method cards on the AlibabaCloud connect step
    this.alibabacloudStaticCredentialsRadio = this.wizardModal.getByRole(
      "radio",
      { name: /^Static access keys/i },
    );
    this.alibabacloudRoleCredentialsRadio = this.wizardModal.getByRole(
      "radio",
      { name: /^RAM role/i },
    );

    // Google Workspace
    this.googleworkspaceProviderRadio = page.getByRole("option", {
      name: /Google Workspace/i,
    });
    this.googleworkspaceCustomerIdInput = page.getByRole("textbox", {
      name: "Customer ID",
    });
    this.googleworkspaceServiceAccountJsonInput = page.getByRole("textbox", {
      name: /Service Account JSON/i,
    });
    this.googleworkspaceDelegatedUserInput = page.getByRole("textbox", {
      name: /Delegated User Email/i,
    });

    // Okta
    this.oktaProviderRadio = page.getByRole("option", {
      name: /Okta/i,
    });
    this.oktaOrgDomainInput = page.getByRole("textbox", {
      name: "Org Domain",
    });
    this.oktaClientIdInput = page.getByRole("textbox", { name: "Client ID" });
    this.oktaPrivateKeyInput = page.getByRole("textbox", {
      name: "Private Key",
    });

    // Vercel
    this.vercelProviderRadio = page.getByRole("option", {
      name: /Vercel/i,
    });
    this.vercelTeamIdInput = page.getByRole("textbox", { name: "Team ID" });
    // API Token is a type="password" field (no textbox role); target by label.
    this.vercelApiTokenInput = page.getByLabel(/API Token/i);

    // Alias input
    this.aliasInput = page.getByRole("textbox", {
      name: "Provider alias (optional)",
    });

    // Connect step footer: one submit for every provider, and Back to the list
    this.connectSubmitButton = page.getByRole("button", {
      name: CONNECT_STEP_SUBMIT_NAME,
    });
    // Only the connection test's verdict, never another alert in the form.
    this.connectionError = this.wizardModal.getByTestId("connection-error");
    this.backButton = page.getByRole("button", { name: "Back" });

    // Button to save the form
    this.saveButton = page.getByRole("button", { name: "Save", exact: true });

    // Button to launch a scan
    this.launchScanButton = page.getByRole("button", {
      name: "Launch scan",
      exact: true,
    });

    // Connection method cards on the connect step. Anchored at the start: a
    // recommended method's card also reads "Recommended".
    this.roleCredentialsRadio = this.wizardModal.getByRole("radio", {
      name: /^IAM Role/,
    });
    this.staticCredentialsRadio = this.wizardModal.getByRole("radio", {
      name: /^Static access keys/,
    });

    this.m365StaticCredentialsRadio = this.wizardModal.getByRole("radio", {
      name: /^App client secret/i,
    });
    this.m365CertificateCredentialsRadio = this.wizardModal.getByRole("radio", {
      name: /^App certificate/i,
    });

    this.gcpServiceAccountRadio = this.wizardModal.getByRole("radio", {
      name: /^Service account key/i,
    });

    this.githubPersonalAccessTokenRadio = this.wizardModal.getByRole("radio", {
      name: /^Personal access token/i,
    });
    this.githubAppCredentialsRadio = this.wizardModal.getByRole("radio", {
      name: /^GitHub App/i,
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

  // Offered on every connect step to a user who can invite (manage_account).
  async selectAwsInviteTeammate(): Promise<void> {
    const invite = this.wizardModal.getByRole("radio", {
      name: /invite a teammate/i,
    });
    await expect(invite).toBeVisible({ timeout: 10000 });
    await invite.click();
    await expect(
      this.wizardModal.getByRole("textbox", { name: /Teammate email/i }),
    ).toBeVisible({ timeout: 10000 });
  }

  // The form preselects a role only when the tenant has one named exactly
  // "admin"; the E2E tenant's is "e2e_admin", so pick the role explicitly.
  async sendTeammateInvitation(
    email: string,
    rolePattern: RegExp = /admin/i,
  ): Promise<void> {
    await this.wizardModal
      .getByRole("textbox", { name: /Teammate email/i })
      .fill(email);
    // Radix Select: the trigger is a combobox and its options render in a portal.
    const roleSelect = this.wizardModal.getByRole("combobox", {
      name: "Select a role",
    });
    await roleSelect.click();
    const option = this.page.getByRole("option", { name: rolePattern }).first();
    await expect(option).toBeVisible({ timeout: 10000 });
    await option.click();
    await expect(roleSelect).not.toContainText("Select a role");
    const send = this.page.getByRole("button", {
      name: "Send invitation",
      exact: true,
    });
    await expect(send).toBeEnabled({ timeout: 10000 });
    await send.click();
  }

  async verifyTeammateInvitationSent(email: string): Promise<void> {
    await expect(
      this.wizardModal.getByText(`Invitation sent to ${email}`),
    ).toBeVisible({ timeout: 15000 });
    await expect(
      this.wizardModal.getByText(/\/invitation\/accept\?invitation_token=/),
    ).toBeVisible();
  }

  // "Done" replaces the submit once the invitation exists and closes the wizard.
  async finishTeammateInvitation(): Promise<void> {
    await this.page.getByRole("button", { name: "Done", exact: true }).click();
    await expect(this.wizardModal).not.toBeVisible();
  }

  // Every provider picks its access method on the connect step itself.
  async selectAwsAccessMethod(type: AWSCredentialType): Promise<void> {
    const accessMethod =
      type === AWS_CREDENTIAL_OPTIONS.AWS_CREDENTIALS
        ? this.staticCredentialsRadio
        : this.roleCredentialsRadio;
    await expect(accessMethod).toBeVisible({ timeout: 10000 });
    await accessMethod.click();
    await expect(accessMethod).toHaveAttribute("aria-checked", "true");
  }

  // AWS, Azure and GCP open on the single-account tab of their connect step.
  private async selectSingleAccountTab(name: string): Promise<void> {
    const singleTab = this.wizardModal.getByRole("tab", { name, exact: true });
    await expect(singleTab).toBeVisible({ timeout: 10000 });
    await singleTab.click();
    await expect(singleTab).toHaveAttribute("aria-selected", "true");
  }

  async selectAzureSingleSubscriptionMethod(): Promise<void> {
    await this.selectSingleAccountTab("Single Azure Subscription");
  }

  async selectGCPSingleProjectMethod(): Promise<void> {
    await this.selectSingleAccountTab("Single GCP Project");
  }

  async selectAWSOrganizationsMethod(): Promise<void> {
    await this.page.getByRole("tab", { name: /Full AWS Organization/ }).click();
  }

  // Saves the account and its credentials and tests the connection in one go.
  // Resolves on the launch step (or once an update closes the wizard); a
  // failed test is reported inline and fails here with its message.
  async submitConnectStep(): Promise<void> {
    await this.verifyWizardModalOpen();
    await expect(this.connectSubmitButton).toBeEnabled({ timeout: 10000 });
    await this.connectSubmitButton.click();

    const pendingRetry = this.page.getByRole("button", {
      name: "Check again",
      exact: true,
    });

    await this.waitForConnectOutcome(pendingRetry);
    await this.throwOnConnectionError();

    // The test outlived its wait without a verdict: ask once more.
    if (await pendingRetry.isVisible().catch(() => false)) {
      await pendingRetry.click();
      await this.waitForConnectOutcome();
      await this.throwOnConnectionError();
    }

    // An update closes the wizard once its test passes.
    if (!(await this.wizardModal.isVisible().catch(() => false))) {
      return;
    }
    await expect(this.launchStepAction).toBeVisible();
  }

  // Waits for the submit to settle: launch step, inline error, pending result
  // or (for an update) the wizard closing.
  private async waitForConnectOutcome(pendingRetry?: Locator): Promise<void> {
    const timeout = 60000;
    const settled = [
      this.launchStepAction.waitFor({ state: "visible", timeout }),
      this.connectionError.waitFor({ state: "visible", timeout }),
      this.wizardModal.waitFor({ state: "hidden", timeout }),
      ...(pendingRetry
        ? [pendingRetry.waitFor({ state: "visible", timeout })]
        : []),
    ].map((outcome) => outcome.catch(() => undefined));

    await Promise.race(settled);
    // Never leave the step mid-submit: the busy label must be gone.
    await expect(
      this.page.getByRole("button", { name: CONNECT_STEP_BUSY_NAME }),
    ).toBeHidden({ timeout });
  }

  private async throwOnConnectionError(): Promise<void> {
    if (await this.connectionError.isVisible().catch(() => false)) {
      const errorText = await this.connectionError.textContent();
      throw new Error(
        `Test connection failed with error: ${errorText?.trim() || "Unknown error"}`,
      );
    }
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

  // The account id is only typed for access keys; with a role it is read from the ARN.
  async fillAWSProviderDetails(data: AWSProviderData): Promise<void> {
    await expect(this.aliasInput).toBeVisible({ timeout: 10000 });
    if (await this.accountIdInput.isVisible().catch(() => false)) {
      await this.accountIdInput.fill(data.accountId);
    }

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
    // Azure also offers the Management Group tab; stay on the single subscription.
    await this.selectAzureSingleSubscriptionMethod();
    await expect(this.azureSubscriptionIdInput).toBeVisible({ timeout: 10000 });
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

  private get launchStepAction(): Locator {
    return this.page.getByRole("button", { name: LAUNCH_STEP_ACTION_NAME });
  }

  // Footer action of the organization flows ("Next", "Authenticate") and of
  // the launch step. The provider connect step submits via submitConnectStep().
  async clickNext(): Promise<void> {
    await this.verifyWizardModalOpen();

    const actionNames = [
      "Go to scans",
      "Authenticate",
      "Next",
      "Save",
      "Save and launch scan",
      "Launch scan",
    ] as const;

    for (const actionName of actionNames) {
      const button = this.page.getByRole("button", {
        name: actionName,
        exact: true,
      });
      if (await button.isVisible().catch(() => false)) {
        await button.click();
        // The launch step's action (see LAUNCH_STEP_ACTION_NAME) closes the modal.
        if (LAUNCH_STEP_ACTION_NAME.test(actionName)) {
          await this.handleLaunchScanCompletion();
        }
        return;
      }
    }

    throw new Error(
      "Could not find an actionable primary button in the provider wizard modal.",
    );
  }

  async completeProviderConnectionWithoutLaunchingScan(
    providerUID: string,
  ): Promise<void> {
    await this.verifyWizardModalOpen();

    // submitConnectStep() already tested the connection; a pass lands here.
    await this.throwOnConnectionError();
    await expect(this.launchStepAction).toBeVisible({ timeout: 30000 });

    // Provider-add E2E validates credentials and provider persistence only.
    // Launching one scan per provider made CI noisy and overloaded the backend;
    // scan execution itself is covered by scans.spec.ts.

    await this.wizardModal
      .getByRole("button", { name: "Close", exact: true })
      .click();
    await expect(this.wizardModal).not.toBeVisible({ timeout: 30000 });
    await this.page.waitForURL(/\/providers/, { timeout: 30000 });
    await this.verifyLoadProviderPageAfterNewProvider();

    const providerExists =
      await this.verifySingleRowForProviderUID(providerUID);
    if (!providerExists) {
      throw new Error(`Provider with UID ${providerUID} was not found.`);
    }
  }

  private async handleLaunchScanCompletion(): Promise<void> {
    const connectionError = this.connectionError;
    const launchErrorToast = this.page.getByRole("alert").filter({
      hasText: /Unable to (launch scan|save scan schedule)/i,
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
    if (credentials.roleArn) {
      await this.roleArnInput.fill(credentials.roleArn);
    }
    // The external id is the tenant's and sits under "Advanced options".
    if (credentials.externalId) {
      if (
        (await this.externalIdInput.isVisible().catch(() => false)) &&
        (await this.externalIdInput.isEditable())
      ) {
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
    if (credentials.homeRegion) {
      await this.ociHomeRegionCombobox.click();
      await this.page
        .locator(`[role="option"][data-value="${credentials.homeRegion}"]`)
        .click();
    }
  }

  async verifyOCICredentialsPageLoaded(): Promise<void> {
    // Verify the OCI credentials page is loaded (add flow - all fields visible)

    await this.verifyPageHasProwlerTitle();
    await expect(this.ociTenancyIdInput).toBeVisible();
    await expect(this.ociUserIdInput).toBeVisible();
    await expect(this.ociFingerprintInput).toBeVisible();
    await expect(this.ociKeyContentInput).toBeVisible();
    await expect(this.ociHomeRegionCombobox).toBeVisible();
  }

  async verifyOCIUpdateCredentialsPageLoaded(): Promise<void> {
    // Verify the OCI update credentials page is loaded
    // Note: Tenancy OCID is hidden in update flow (auto-populated from provider UID)

    await this.verifyPageHasProwlerTitle();
    await expect(this.ociUserIdInput).toBeVisible();
    await expect(this.ociFingerprintInput).toBeVisible();
    await expect(this.ociKeyContentInput).toBeVisible();
    await expect(this.ociHomeRegionCombobox).toBeVisible();
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

  async selectGoogleWorkspaceProvider(): Promise<void> {
    await this.selectProviderRadio(this.googleworkspaceProviderRadio);
  }

  async fillGoogleWorkspaceProviderDetails(
    data: GoogleWorkspaceProviderData,
  ): Promise<void> {
    await this.googleworkspaceCustomerIdInput.fill(data.customerId);

    if (data.alias) {
      await this.aliasInput.fill(data.alias);
    }
  }

  async fillGoogleWorkspaceCredentials(
    credentials: GoogleWorkspaceProviderCredential,
  ): Promise<void> {
    if (credentials.serviceAccountJson) {
      await this.googleworkspaceServiceAccountJsonInput.fill(
        credentials.serviceAccountJson,
      );
    }
    if (credentials.delegatedUser) {
      await this.googleworkspaceDelegatedUserInput.fill(
        credentials.delegatedUser,
      );
    }
  }

  async verifyGoogleWorkspaceCredentialsPageLoaded(): Promise<void> {
    await this.verifyPageHasProwlerTitle();
    await expect(this.googleworkspaceServiceAccountJsonInput).toBeVisible();
    await expect(this.googleworkspaceDelegatedUserInput).toBeVisible();
  }

  async selectOktaProvider(): Promise<void> {
    await this.selectProviderRadio(this.oktaProviderRadio);
  }

  async fillOktaProviderDetails(data: OktaProviderData): Promise<void> {
    // Fill the Okta provider details (org domain is lowercased by the form)

    await this.oktaOrgDomainInput.fill(data.orgDomain);

    if (data.alias) {
      await this.aliasInput.fill(data.alias);
    }
  }

  async fillOktaCredentials(
    credentials: OktaProviderCredential,
  ): Promise<void> {
    // Fill the Okta OAuth 2.0 Private Key JWT credentials form

    if (credentials.clientId) {
      await this.oktaClientIdInput.fill(credentials.clientId);
    }
    if (credentials.privateKey) {
      await this.oktaPrivateKeyInput.fill(credentials.privateKey);
    }
  }

  async verifyOktaCredentialsPageLoaded(): Promise<void> {
    // Verify the Okta credentials page is loaded

    await this.verifyPageHasProwlerTitle();
    await expect(this.oktaClientIdInput).toBeVisible();
    await expect(this.oktaPrivateKeyInput).toBeVisible();
  }

  async selectVercelProvider(): Promise<void> {
    await this.selectProviderRadio(this.vercelProviderRadio);
  }

  async fillVercelProviderDetails(data: VercelProviderData): Promise<void> {
    // Fill the Vercel provider details (Team ID is the provider UID)

    await this.vercelTeamIdInput.fill(data.teamId);

    if (data.alias) {
      await this.aliasInput.fill(data.alias);
    }
  }

  async fillVercelCredentials(
    credentials: VercelProviderCredential,
  ): Promise<void> {
    // Fill the Vercel credentials form

    if (credentials.apiToken) {
      await this.vercelApiTokenInput.fill(credentials.apiToken);
    }
  }

  async verifyVercelCredentialsPageLoaded(): Promise<void> {
    // Verify the Vercel credentials page is loaded

    await this.verifyPageHasProwlerTitle();
    await expect(this.vercelApiTokenInput).toBeVisible();
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
    await expect(this.googleworkspaceProviderRadio).toBeVisible();
    await expect(this.oktaProviderRadio).toBeVisible();
    await expect(this.vercelProviderRadio).toBeVisible();
  }

  async verifyCredentialsPageLoaded(): Promise<void> {
    await this.verifyPageHasProwlerTitle();
    await this.verifyWizardModalOpen();

    // The AWS connect step: its method cards and, by default, the role form.
    await expect(this.roleCredentialsRadio).toBeVisible({ timeout: 20000 });
    await expect(
      this.wizardModal.getByRole("textbox", { name: "Role ARN" }),
    ).toBeVisible({ timeout: 20000 });
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
    await expect(this.kubernetesKubeconfigContentInput).toBeVisible();
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

    // The connection is tested on the connect step, so only the launch action is left.
    await expect(this.launchStepAction).toBeVisible();
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

    // Use an auto-retrying assertion (not an instant count()) so the check
    // waits for the table refetch to render the newly added provider row.
    try {
      await expect(matchingRows).toHaveCount(1, { timeout: 15000 });
      return true;
    } catch {
      return false;
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
    // The wizard opens on the provider's connect step with only its credentials:
    // "Cancel" closes it and "Save and test" saves and tests them.
    await this.verifyPageHasProwlerTitle();
    await this.verifyWizardModalOpen();
    await expect(
      this.page.getByRole("button", { name: "Save and test", exact: true }),
    ).toBeVisible();
    await expect(
      this.page.getByRole("button", { name: "Cancel", exact: true }),
    ).toBeVisible();
  }

  async verifyCredentialsUpdated(): Promise<void> {
    // A passed test closes an update; "Add Credentials" (no secret yet) goes
    // on to the launch step instead.
    await this.verifyPageHasProwlerTitle();
    await this.throwOnConnectionError();

    if (await this.launchStepAction.isVisible().catch(() => false)) {
      return;
    }

    await expect(this.wizardModal).not.toBeVisible({ timeout: 30000 });
    await expect(this.providersTable).toBeVisible({ timeout: 30000 });
  }
}
