import { expect, type Locator, type Page } from "@playwright/test";

import { BasePage } from "../base-page";

export class NavigationPage extends BasePage {
  readonly appSidebar: Locator;
  readonly closeMenuButton: Locator;
  readonly openMenuButton: Locator;

  constructor(page: Page) {
    super(page);
    this.appSidebar = page.getByRole("dialog", { name: "App sidebar" });
    this.closeMenuButton = page.getByRole("button", { name: "Close menu" });
    this.openMenuButton = page.getByRole("button", { name: "Open menu" });
  }

  async goto(): Promise<void> {
    await super.goto("/");
  }

  async verifyPageLoaded(): Promise<void> {
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
