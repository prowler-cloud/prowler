import { Page, Locator, expect } from "@playwright/test";

export class HomePage {
  readonly page: Page;
  
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
  readonly themeToggle: Locator;
  readonly logo: Locator;

  constructor(page: Page) {
    this.page = page;
    
    // Main content elements
    this.mainContent = page.locator("main");
    this.breadcrumbs = page.getByLabel("Breadcrumbs");
    this.overviewHeading = page.getByRole("heading", { name: "Overview", exact: true });
    
    // Navigation elements
    this.navigationMenu = page.locator("nav");
    this.userMenu = page.getByRole("button", { name: /user menu/i });
    this.signOutButton = page.getByRole("button", { name: "Sign out" });
    
    // Dashboard elements
    this.dashboardCards = page.locator('[data-testid="dashboard-card"]');
    this.overviewSection = page.locator('[data-testid="overview-section"]');
    
    // UI elements
    this.themeToggle = page.getByLabel("Toggle theme");
    this.logo = page.locator('svg[width="300"]');
  }

  // Navigation methods
  async goto(): Promise<void> {
    await this.page.goto("/");
    await this.waitForPageLoad();
  }

  async waitForPageLoad(): Promise<void> {
    await this.page.waitForLoadState("networkidle");
  }

  // Verification methods
  async verifyPageLoaded(): Promise<void> {
    await expect(this.page).toHaveURL("/");
    await expect(this.mainContent).toBeVisible();
    await expect(this.overviewHeading).toBeVisible();
    await this.page.waitForLoadState('networkidle');
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

  async openUserMenu(): Promise<void> {
    await this.userMenu.click();
  }

  async signOut(): Promise<void> {
    await this.openUserMenu();
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
  async refresh(): Promise<void> {
    await this.page.reload();
    await this.waitForPageLoad();
  }

  async goBack(): Promise<void> {
    await this.page.goBack();
    await this.waitForPageLoad();
  }

  // Accessibility methods
  async verifyKeyboardNavigation(): Promise<void> {
    // Test tab navigation through main elements
    await this.page.keyboard.press("Tab");
    await expect(this.themeToggle).toBeFocused();
  }

  // Wait methods
  async waitForRedirect(expectedUrl: string): Promise<void> {
    await this.page.waitForURL(expectedUrl);
  }

  async waitForContentLoad(): Promise<void> {
    await this.page.waitForFunction(() => {
      const main = document.querySelector("main");
      return main && main.offsetHeight > 0;
    });
  }
}
