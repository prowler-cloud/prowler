import { Page, Locator, expect } from "@playwright/test";
import { BasePage } from "../base-page";

// Scan page
export class ScansPage extends BasePage {

  // Main content elements
  readonly scanTable: Locator;
  constructor(page: Page) {
    super(page);

    // Main content elements
    this.scanTable = page.locator("table");

  }

  // Navigation methods
  async goto(): Promise<void> {
    await super.goto("/scans");
  }

  // Verification methods
  async verifyPageLoaded(): Promise<void> {
    await expect(this.page).toHaveTitle(/Prowler/);
    await expect(this.scanTable).toBeVisible();
  }
}
