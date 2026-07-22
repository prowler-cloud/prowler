import { Locator, Page, expect, request } from "@playwright/test";
import {
  AWSProviderCredential,
  AWSProviderData,
  AWS_CREDENTIAL_OPTIONS,
  ProvidersPage,
} from "./providers/providers-page";

export const ERROR_MESSAGES = {
  INVALID_CREDENTIALS: "Invalid email or password",
  INVALID_EMAIL: "Please enter a valid email address.",
  PASSWORD_REQUIRED: "Password is required.",
} as const;

export const URLS = {
  LOGIN: "/sign-in",
  SIGNUP: "/sign-up",
  DASHBOARD: "/",
  PROFILE: "/profile",
} as const;

export const TEST_CREDENTIALS = {
  VALID: {
    email: process.env.E2E_ADMIN_USER || "e2e@prowler.com",
    password: process.env.E2E_ADMIN_PASSWORD || "Thisisapassword123@",
  },
  INVALID: {
    email: "invalid@example.com",
    password: "wrongPassword",
  },
  INVALID_EMAIL_FORMAT: {
    email: "invalid-email",
    password: "somepassword",
  },
} as const;

/**
 * Generate a random base36 suffix of specified length
 * Used for creating unique test data to avoid conflicts
 */
export function makeSuffix(len: number): string {
  let s = "";
  while (s.length < len) {
    s += Math.random().toString(36).slice(2);
  }
  return s.slice(0, len);
}

export async function getSession(page: Page) {
  const response = await page.request.get("/api/auth/session");
  return response.json();
}

export async function getSessionWithoutCookies(page: Page) {
  const currentUrl = page.url();
  const baseUrl = currentUrl.startsWith("http")
    ? new URL(currentUrl).origin
    : process.env.NEXTAUTH_URL || "http://localhost:3000";

  const apiContext = await request.newContext({ baseURL: baseUrl });
  const response = await apiContext.get("/api/auth/session");
  const session = await response.json();
  await apiContext.dispose();

  return session;
}

export async function verifySessionValid(page: Page) {
  const session = await getSession(page);
  expect(session).toBeTruthy();
  expect(session.user).toBeTruthy();
  expect(session.accessToken).toBeTruthy();
  expect(session.refreshToken).toBeTruthy();
  return session;
}

export async function addAWSProvider(
  page: Page,
  accountId: string,
  accessKey: string,
  secretKey: string,
): Promise<void> {
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

  // Create providers page object
  const providersPage = new ProvidersPage(page);

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

  // Verify credentials page is loaded
  await providersPage.verifyCredentialsPageLoaded();

  // Select static credentials type
  await providersPage.selectCredentialsType(
    AWS_CREDENTIAL_OPTIONS.AWS_CREDENTIALS,
  );
  // Fill static credentials
  await providersPage.fillStaticCredentials(staticCredentials);
  await providersPage.clickNext();

  // Scans specs launch their own scan. The setup helper should only leave a
  // connected provider behind so the suite does not spend CI capacity on a
  // duplicate preparatory scan.
  await providersPage.completeProviderConnectionWithoutLaunchingScan(accountId);
}

/**
 * Finds a provider after the filtered providers page reaches a loaded state.
 * The loading skeleton also renders a table, so table visibility alone cannot
 * prove that provider data is ready.
 */
async function findProviderRow(
  page: ProvidersPage,
  providerUID: string,
): Promise<Locator | null> {
  await page.page.goto(
    `/providers?filter%5Bsearch%5D=${encodeURIComponent(providerUID)}`,
  );

  const providerRow = page.providersTable
    .locator("tbody tr")
    .filter({ hasText: providerUID })
    .first();
  const noResults = page.providersTable.getByRole("cell", {
    name: "No results.",
    exact: true,
  });
  const emptyState = page.page.getByRole("region", {
    name: /no providers configured/i,
  });

  await expect(providerRow.or(noResults).or(emptyState)).toBeVisible({
    timeout: 10000,
  });

  if (await providerRow.isVisible().catch(() => false)) {
    return providerRow;
  }

  return null;
}

export async function deleteProviderIfExists(
  page: ProvidersPage,
  providerUID: string,
): Promise<void> {
  // Find the provider row
  const targetRow = await findProviderRow(page, providerUID);

  if (!targetRow) {
    // Provider not found, nothing to delete
    return;
  }

  // Find and click the action button (last cell = actions column)
  const actionButton = targetRow.locator("td").last().locator("button").first();

  // Ensure the button is in view before clicking (handles horizontal scroll)
  await actionButton.scrollIntoViewIfNeeded();
  // Verify the button is visible
  await expect(actionButton).toBeVisible({ timeout: 5000 });
  await actionButton.click();

  // Wait for dropdown menu to appear and find delete option
  const deleteMenuItem = page.page.getByRole("menuitem", {
    name: /delete.*provider/i,
  });

  await expect(deleteMenuItem).toBeVisible({ timeout: 5000 });
  await deleteMenuItem.click();

  // Wait for confirmation modal to appear. Exclude the Next.js dev error
  // overlay, which is also role="dialog" and would otherwise be matched first,
  // making the assertion wait on the wrong (hidden) element.
  const modal = page.page
    .locator(
      '[role="dialog"]:not([data-nextjs-dialog="true"]), .modal, [data-testid*="modal"]',
    )
    .first();

  await expect(modal).toBeVisible({ timeout: 10000 });

  // Find and click the delete confirmation button
  await expect(page.deleteProviderConfirmationButton).toBeVisible({
    timeout: 5000,
  });
  await page.deleteProviderConfirmationButton.click();

  // Wait for modal to close (this indicates deletion was initiated)
  await expect(modal).not.toBeVisible({ timeout: 10000 });

  // The success notification is shown only after the delete request completes.
  await expect(
    page.page.getByText("The provider was removed successfully.", {
      exact: true,
    }),
  ).toBeVisible({ timeout: 10000 });

  // Reload a server-filtered view and prove the provider no longer exists.
  const deletedProviderRow = await findProviderRow(page, providerUID);
  expect(
    deletedProviderRow,
    `Provider ${providerUID} still exists after deletion`,
  ).toBeNull();
}
