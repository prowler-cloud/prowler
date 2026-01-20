import { Page, Locator, expect } from "@playwright/test";
import { BasePage } from "../base-page";

export class HomePage extends BasePage {

  // Main content elements
  readonly mainContent: Locator;
  readonly breadcrumbs: Locator;
  readonly overviewHeading: Locator;

  // Navigation elements
  readonly navigationMenu: Locator;
  readonly userMenu: Locator;
  readonly signOutButton: Locator;

  // Dashboard elements
  readonly dashboardCards: Locator;
  readonly overviewSection: Locator;

  // UI elements
  readonly logo: Locator;

  constructor(page: Page) {
    super(page);

    // Main content elements
    this.mainContent = page.locator("main");
    this.breadcrumbs = page.getByRole("navigation", { name: "Breadcrumbs" });
    this.overviewHeading = page.getByRole("heading", { name: "Overview", exact: true });

    // Navigation elements
    this.navigationMenu = page.locator("nav");
    // Sign out is a direct button, not inside a menu
    this.userMenu = page.getByRole("button", { name: "Sign out" });
    this.signOutButton = page.getByRole("button", { name: "Sign out" });

    // Dashboard elements
    this.dashboardCards = page.locator('[data-testid="dashboard-card"]');
    this.overviewSection = page.locator('[data-testid="overview-section"]');

    // UI elements
    this.logo = page.locator('svg[width="300"]');
  }

  // Navigation methods
  async goto(): Promise<void> {
    await super.goto("/");
  }

  // Verification methods
  async verifyPageLoaded(): Promise<void> {
    await expect(this.page).toHaveURL("/");
    await expect(this.mainContent).toBeVisible();
    await expect(this.overviewHeading).toBeVisible();
  }

  async verifyBreadcrumbs(): Promise<void> {
    await expect(this.breadcrumbs).toBeVisible();
    await expect(this.overviewHeading).toBeVisible();
  }

  async verifyMainContent(): Promise<void> {
    await expect(this.mainContent).toBeVisible();
  }

  // Navigation methods
  async navigateToOverview(): Promise<void> {
    await this.overviewHeading.click();
  }

  async signOut(): Promise<void> {
    // Wait for navbar to be visible before clicking sign out
    const navbar = this.page.locator("header");
    await navbar.waitFor({ state: "visible" });
    await this.signOutButton.click();
  }

  // Dashboard methods
  async verifyDashboardCards(): Promise<void> {
    await expect(this.dashboardCards.first()).toBeVisible();
  }

  async verifyOverviewSection(): Promise<void> {
    await expect(this.overviewSection).toBeVisible();
  }

  // Utility methods

  // Accessibility methods
  async verifyKeyboardNavigation(): Promise<void> {
    // Test tab navigation through main elements
    await this.page.keyboard.press("Tab");
    await expect(this.themeToggle).toBeFocused();
  }

  async waitForContentLoad(): Promise<void> {
    await this.page.waitForFunction(() => {
      const main = document.querySelector("main");
      return main && main.offsetHeight > 0;
    });
  }
}
