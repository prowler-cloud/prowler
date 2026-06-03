import { Locator, Page, expect } from "@playwright/test";

import { BasePage } from "../base-page";

// localStorage key prefix used by the tour completion store
// (`prowler.tour.<tourId>.v<version>`). Kept here so the cleanup helper never
// hand-builds keys elsewhere in the suite.
const TOUR_KEY_PREFIX = "prowler.tour";
const ADD_PROVIDER_TOUR_KEY = `${TOUR_KEY_PREFIX}.add-provider.v1`;

// Page Object for the onboarding flows. URL assertions live here (per the
// prowler-test-ui convention) so the spec only orchestrates user actions.
export class OnboardingPage extends BasePage {
  // Welcome modal (mandatory gate entry point) and its actions.
  readonly welcomeModal: Locator;
  readonly getStartedButton: Locator;
  readonly skipButton: Locator;

  // Tour anchors mounted on the providers surface.
  readonly addProviderTriggerAnchor: Locator;
  readonly providerTypeAnchor: Locator;

  // User-nav restart entry point.
  readonly accountMenuTrigger: Locator;
  readonly productTourNavEntry: Locator;

  constructor(page: Page) {
    super(page);

    this.welcomeModal = page.getByRole("dialog").filter({
      has: page.getByRole("heading", { name: /Add your first provider/i }),
    });
    this.getStartedButton = page.getByRole("button", { name: "Get started" });
    this.skipButton = page.getByRole("button", { name: "Skip for now" });

    this.addProviderTriggerAnchor = page.locator(
      '[data-tour-id="add-provider-trigger"]',
    );
    this.providerTypeAnchor = page.locator(
      '[data-tour-id="add-provider-provider-type"]',
    );

    this.accountMenuTrigger = page.getByRole("button", {
      name: "Account menu",
    });
    this.productTourNavEntry = page.getByRole("menuitem", {
      name: "Product tour",
    });
  }

  // Clear every `prowler.tour.*` key so the gate evaluates as a fresh browser.
  async clearOnboardingState(): Promise<void> {
    await this.page.evaluate((prefix) => {
      const keys: string[] = [];
      for (let i = 0; i < window.localStorage.length; i++) {
        const key = window.localStorage.key(i);
        if (key && key.startsWith(prefix)) keys.push(key);
      }
      keys.forEach((key) => window.localStorage.removeItem(key));
    }, TOUR_KEY_PREFIX);
  }

  // Seed a `completed` record so the restart path proves the tour starts despite
  // an existing completion record.
  async seedCompletedAddProviderRecord(): Promise<void> {
    await this.page.evaluate((key) => {
      window.localStorage.setItem(
        key,
        JSON.stringify({
          tourId: "add-provider",
          version: 1,
          state: "completed",
          completedAt: new Date().toISOString(),
        }),
      );
    }, ADD_PROVIDER_TOUR_KEY);
  }

  async openAccountMenu(): Promise<void> {
    await this.accountMenuTrigger.click();
  }

  async startProductTourFromNav(): Promise<void> {
    await this.openAccountMenu();
    await expect(this.productTourNavEntry).toBeVisible();
    await this.productTourNavEntry.click();
  }

  async clickGetStarted(): Promise<void> {
    await this.getStartedButton.click();
  }

  async verifyWelcomeModalVisible(): Promise<void> {
    await expect(this.welcomeModal).toBeVisible();
  }

  async verifyWelcomeModalNotVisible(): Promise<void> {
    await expect(this.welcomeModal).not.toBeVisible();
  }

  async verifyTriggerAnchorPresent(): Promise<void> {
    await expect(this.addProviderTriggerAnchor).toBeVisible();
  }

  async verifyAnchorsPresent(): Promise<void> {
    await expect(this.addProviderTriggerAnchor).toBeVisible();
    await expect(this.providerTypeAnchor).toBeVisible();
  }

  // URL assertions encapsulated in the POM (prowler-test-ui convention).
  async verifyOnProvidersPage(): Promise<void> {
    await this.page.waitForURL(/\/providers(\?|$)/);
  }

  async verifyOnProvidersPageWithOnboardingParam(): Promise<void> {
    await this.page.waitForURL(/\/providers\?onboarding=add-provider/);
  }
}
