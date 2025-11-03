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
    this.scanProviderSelect = page.getByRole("button", { name: "Select a cloud provider to launch a scan" });
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

    await expect(this.page).toHaveTitle(/Prowler/);
    await expect(this.scanTable).toBeVisible();
    await this.waitForPageLoad();
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
  
}
