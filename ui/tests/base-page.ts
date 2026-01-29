import { Page, Locator, expect } from "@playwright/test";

/**
 * Base page object class containing common functionality
 * that can be shared across all page objects
 */
export abstract class BasePage {
  readonly page: Page;

  // Common UI elements that appear on most pages
  readonly title: Locator;
  readonly loadingIndicator: Locator;
  readonly themeToggle: Locator;

  constructor(page: Page) {
    this.page = page;

    // Common locators that most pages share
    this.title = page.locator("h1, h2, [role='heading']").first();
    this.loadingIndicator = page.getByRole("status", { name: "Loading" });
    this.themeToggle = page.getByRole("button", { name: "Toggle theme" });
  }

  // Common navigation methods
  async goto(url: string): Promise<void> {
    await this.page.goto(url);
  }

  /**
   * Navigate to URL waiting only for server response (commit).
   * Use this after clearing cookies to ensure middleware runs fresh.
   */
  async gotoFresh(url: string): Promise<void> {
    await this.page.goto(url, { waitUntil: "commit" });
  }

  async refresh(): Promise<void> {
    await this.page.reload();
  }

  async goBack(): Promise<void> {
    await this.page.goBack();
  }

  // Common verification methods
  async verifyPageTitle(expectedTitle: string | RegExp): Promise<void> {
    await expect(this.page).toHaveTitle(expectedTitle);
  }

  async verifyLoadingState(): Promise<void> {
    await expect(this.loadingIndicator).toBeVisible();
  }

  async verifyNoLoadingState(): Promise<void> {
    await expect(this.loadingIndicator).not.toBeVisible();
  }

  // Common form interaction methods
  async clearInput(input: Locator): Promise<void> {
    await input.clear();
  }

  async fillInput(input: Locator, value: string): Promise<void> {
    await input.fill(value);
  }

  async clickButton(button: Locator): Promise<void> {
    await button.click();
  }

  // Common validation methods
  async verifyElementVisible(element: Locator): Promise<void> {
    await expect(element).toBeVisible();
  }

  async verifyElementNotVisible(element: Locator): Promise<void> {
    await expect(element).not.toBeVisible();
  }

  async verifyElementText(element: Locator, expectedText: string): Promise<void> {
    await expect(element).toHaveText(expectedText);
  }

  async verifyElementContainsText(element: Locator, expectedText: string): Promise<void> {
    await expect(element).toContainText(expectedText);
  }

  // Common accessibility methods
  async verifyKeyboardNavigation(elements: Locator[]): Promise<void> {
    for (const element of elements) {
      await this.page.keyboard.press("Tab");
      await expect(element).toBeFocused();
    }
  }

  async verifyAriaLabels(elements: { locator: Locator; expectedLabel: string }[]): Promise<void> {
    for (const { locator, expectedLabel } of elements) {
      await expect(locator).toHaveAttribute("aria-label", expectedLabel);
    }
  }

  // Common utility methods
  async getElementText(element: Locator): Promise<string> {
    return await element.textContent() || "";
  }

  async getElementValue(element: Locator): Promise<string> {
    return await element.inputValue();
  }

  async isElementVisible(element: Locator): Promise<boolean> {
    return await element.isVisible();
  }

  async isElementEnabled(element: Locator): Promise<boolean> {
    return await element.isEnabled();
  }

  // Common error handling methods
  async getFormErrors(): Promise<string[]> {
    const errorElements = await this.page.locator('[role="alert"], .error-message, [data-testid="error"]').all();
    const errors: string[] = [];

    for (const element of errorElements) {
      const text = await element.textContent();
      if (text) {
        errors.push(text.trim());
      }
    }

    return errors;
  }

  async verifyNoErrors(): Promise<void> {
    const errors = await this.getFormErrors();
    expect(errors).toHaveLength(0);
  }

  // Common wait methods
  async waitForElement(element: Locator, timeout: number = 5000): Promise<void> {

    await element.waitFor({ timeout });
  }

  async waitForElementToDisappear(element: Locator, timeout: number = 5000): Promise<void> {

    await element.waitFor({ state: "hidden", timeout });
  }

  async waitForUrl(expectedUrl: string | RegExp, timeout: number = 5000): Promise<void> {

    await this.page.waitForURL(expectedUrl, { timeout });
  }

  // Common screenshot methods
  async takeScreenshot(name: string): Promise<void> {

    await this.page.screenshot({ path: `screenshots/${name}.png` });
  }

  async takeElementScreenshot(element: Locator, name: string): Promise<void> {

    await element.screenshot({ path: `screenshots/${name}.png` });
  }
}
