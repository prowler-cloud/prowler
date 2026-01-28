import { Locator, Page, expect } from "@playwright/test";
import { AWSProviderCredential, AWSProviderData, AWS_CREDENTIAL_OPTIONS, ProvidersPage } from "./providers/providers-page";
import { ScansPage } from "./scans/scans-page";

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

  // Launch scan
  await providersPage.verifyLaunchScanPageLoaded();
  await providersPage.clickNext();

  // Wait for redirect to provider page
  const scansPage = new ScansPage(page);
  await scansPage.verifyPageLoaded();
}

export async function deleteProviderIfExists(page: ProvidersPage, providerUID: string): Promise<void> {
  // Delete the provider if it exists

  // Navigate to providers page
  await page.goto();
  await expect(page.providersTable).toBeVisible({ timeout: 10000 });

  // Find and use the search input to filter the table
  const searchInput = page.page.getByPlaceholder(/search|filter/i);

  await expect(searchInput).toBeVisible({ timeout: 5000 });

  // Clear and search for the specific provider
  await searchInput.clear();
  await searchInput.fill(providerUID);
  await searchInput.press("Enter");

  // Additional wait for React table to re-render with the server-filtered data
  // The filtering happens on the server, but the table component needs time
  // to process the response and update the DOM after network idle
  await page.page.waitForTimeout(1500);

  // Get all rows from the table
  const allRows = page.providersTable.locator("tbody tr");

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

    await findProviderRow();
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
    await page.goto();
    await expect(page.providersTable).toBeVisible({ timeout: 10000 });
    return;
  }

  // Find and click the action button (last cell = actions column)
  const actionButton = targetRow
    .locator("td")
    .last()
    .locator("button")
    .first();

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

  // Wait for confirmation modal to appear
  const modal = page.page
    .locator('[role="dialog"], .modal, [data-testid*="modal"]')
    .first();

  await expect(modal).toBeVisible({ timeout: 10000 });

  // Find and click the delete confirmation button
  await expect(page.deleteProviderConfirmationButton).toBeVisible({
    timeout: 5000,
  });
  await page.deleteProviderConfirmationButton.click();

  // Wait for modal to close (this indicates deletion was initiated)
  await expect(modal).not.toBeVisible({ timeout: 10000 });

  // Navigate back to providers page to ensure clean state
  await page.goto();
  await expect(page.providersTable).toBeVisible({ timeout: 10000 });
}
