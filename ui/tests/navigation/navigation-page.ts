import { expect, type Locator, type Page } from "@playwright/test";

import { BasePage } from "../base-page";
import { SignInPage } from "../sign-in-base/sign-in-base-page";

export class NavigationPage extends BasePage {
  readonly appSidebar: Locator;
  readonly closeMenuButton: Locator;
  readonly openMenuButton: Locator;
  readonly providersLink: Locator;
  readonly feedbackTrigger: Locator;
  readonly signInPage: SignInPage;

  constructor(page: Page) {
    super(page);
    this.appSidebar = page.getByRole("dialog", { name: "App sidebar" });
    this.closeMenuButton = page.getByRole("button", { name: "Close menu" });
    this.openMenuButton = page.getByRole("button", { name: "Open menu" });
    this.providersLink = page.getByRole("link", {
      name: "Providers",
      exact: true,
    });
    this.feedbackTrigger = page.getByRole("button", { name: "Give feedback" });
    this.signInPage = new SignInPage(page);
  }

  async goto(): Promise<void> {
    await super.goto("/");
  }

  async navigateToProviders(): Promise<void> {
    await this.openMobileSidebar();
    await this.providersLink.click();
    await expect(this.page).toHaveURL(/\/providers/);
  }

  async gotoSignIn(): Promise<void> {
    await this.signInPage.goto();
  }

  async verifySignInPageLoaded(): Promise<void> {
    await expect(this.signInPage.pageTitle).toBeVisible();
  }

  async blockPostHogRequests(): Promise<void> {
    // The feedback survey is backed by PostHog; blocking its host simulates a
    // third-party outage. Navigation and the rest of the app must stay usable.
    await Promise.all([
      this.page.route("https://*.posthog.com/**", (route) => route.abort()),
      this.page.route("https://*.i.posthog.com/**", (route) => route.abort()),
    ]);
  }

  async verifyFeedbackTriggerAbsent(): Promise<void> {
    await expect(this.feedbackTrigger).toHaveCount(0);
  }

  async verifyPageLoaded(): Promise<void> {
    const tourDialogButton = this.page.getByRole("button", { name: "Got it" });
    if (await tourDialogButton.isVisible()) {
      await tourDialogButton.click();
    }

    const providerDialogButton = this.page.getByRole("button", {
      name: "Skip for now",
    });
    if (await providerDialogButton.isVisible()) {
      await providerDialogButton.click();
    }

    await expect(this.openMenuButton).toBeVisible();
  }

  async openMobileSidebar(): Promise<void> {
    await this.openMenuButton.click();
    await expect(this.appSidebar).toBeVisible();
    await expect(this.openMenuButton).toBeHidden();
    await this.appSidebar.evaluate(async (element) => {
      await Promise.all(
        element
          .getAnimations()
          .map((animation) => animation.finished.catch(() => undefined)),
      );
    });
  }

  async verifyMobileSidebarFitsViewport(): Promise<void> {
    const viewport = this.page.viewportSize();
    const sidebarBox = await this.appSidebar.boundingBox();
    const closeButtonBox = await this.closeMenuButton.boundingBox();

    expect(viewport).not.toBeNull();
    expect(sidebarBox).not.toBeNull();
    expect(closeButtonBox).not.toBeNull();

    if (!viewport || !sidebarBox || !closeButtonBox) return;

    for (const box of [sidebarBox, closeButtonBox]) {
      expect(box.x).toBeGreaterThanOrEqual(0);
      expect(box.y).toBeGreaterThanOrEqual(0);
      expect(box.x + box.width).toBeLessThanOrEqual(viewport.width);
      expect(box.y + box.height).toBeLessThanOrEqual(viewport.height);
    }

    const bodyWidth = await this.page.locator("body").evaluate((element) => ({
      clientWidth: element.clientWidth,
      scrollWidth: element.scrollWidth,
    }));
    expect(bodyWidth.scrollWidth).toBeLessThanOrEqual(bodyWidth.clientWidth);
  }
}
