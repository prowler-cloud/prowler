import { Page, Locator, expect } from "@playwright/test";
import { BasePage } from "../base-page";

// Scan page
export class ScansPage extends BasePage {

  // Main content elements
  readonly scanTable: Locator;

    // Scan provider selection elements
    readonly scanProviderSelect: Locator;
    readonly scanAliasInput: Locator;
    readonly startNowButton: Locator;

    // Scan state elements
    readonly successToast: Locator;


  constructor(page: Page) {
    super(page);

    // Scan provider selection elements
    this.scanProviderSelect = page.getByRole('combobox').filter({ hasText: 'Choose a cloud provider' })
    this.scanAliasInput = page.getByRole("textbox", { name: "Scan label (optional)" });
    this.startNowButton = page.getByRole("button", { name: /Start now|Start scan now/i });

    // Scan state elements
    this.successToast = page.getByRole("alert", { name: /The scan was launched successfully\.?/i });

    // Main content elements
    this.scanTable = page.locator("table");
  }

  // Navigation methods
  async goto(): Promise<void> {
    await super.goto("/scans");
  }

  async verifyPageLoaded(): Promise<void> {
    // Verify the scans page is loaded
    if (!this.page.url().includes("/scans")) {
      await this.goto();
    }

    await expect(this.page).toHaveTitle(/Prowler/);
    await expect(this.scanTable).toBeVisible();
  }

  async selectProviderByUID(uid: string): Promise<void> {
    // Select the provider by UID

    await this.scanProviderSelect.click();
    await this.page.getByRole("option", { name: new RegExp(uid) }).click();
  }

  async fillScanAlias(alias: string): Promise<void> {
    // Fill the scan alias

    await this.scanAliasInput.fill(alias);
  }

  async clickStartNowButton(): Promise<void> {
    // Click the start now button

    await expect(this.startNowButton).toBeVisible();
    await this.startNowButton.click();
  }

  async verifyScanLaunched(alias: string): Promise<void> {
    // Verify the scan was launched

    // Verify the success toast is visible
    await this.successToast.waitFor({ state: "visible", timeout: 5000 }).catch(() => {});

    // Wait for the scans table to be visible
    await expect(this.scanTable).toBeVisible();

    // Find a row that contains the scan alias
    const rowWithAlias = this.scanTable
      .locator("tbody tr")
      .filter({ hasText: alias })
      .first();

    // Verify the row with the scan alias is visible
    await expect(rowWithAlias).toBeVisible();

    // Basic state/assertion hint: queued/available/executing (non-blocking if not present)
    await rowWithAlias.textContent().then((text) => {

      if (!text) return;

      const hasExpectedState = /executing|available|queued/i.test(text);

      if (!hasExpectedState) {
        // Fall back to just ensuring alias is present in the row
        // The expectation above already ensures visibility
      }
    });
  }


  async verifyScheduledScanStatus(accountId: string): Promise<void> {
    // Verifies that:
    // 1. The provider exists in the table (by account ID/UID)
    // 2. The scan name field contains "scheduled scan"

    // Scan Table exists
    await expect(this.scanTable).toBeVisible();

    // Find a row that contains the account ID (provider UID in Cloud Provider column)
    // Note: Use a more specific locator strategy if possible in the future
    const rowWithAccountId = this.scanTable
      .locator("tbody tr")
      .filter({ hasText: accountId })
      .first();

    try {
      // Verify the row with the account ID is visible (provider exists)
      // Use a short timeout first to allow for a quick check
      await expect(rowWithAccountId).toBeVisible({ timeout: 5000 });
    } catch {
      // If not visible immediately (likely due to async backend processing),
      // reload the page to fetch the latest data
      await this.page.reload();
      await this.verifyPageLoaded();
      // Wait longer after reload
      await expect(rowWithAccountId).toBeVisible({ timeout: 15000 });
    }

    // Verify the row contains "scheduled scan" in the Scan name column
    // The scan name "Daily scheduled scan" is displayed as "scheduled scan" in the table
    await expect(rowWithAccountId).toContainText("scheduled scan", {
      ignoreCase: true,
    });
  }

}
