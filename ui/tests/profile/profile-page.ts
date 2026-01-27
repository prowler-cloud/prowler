import { Page, Locator, expect } from "@playwright/test";
import { BasePage } from "../base-page";

export class UserProfilePage extends BasePage {
  // Page heading
  readonly pageHeadingUserProfile: Locator;

  constructor(page: Page) {
    super(page);

    // Page heading
    this.pageHeadingUserProfile = page.getByRole("heading", {
      name: "User Profile",
    });
  }

  async goto(): Promise<void> {
    await super.goto("/profile");
  }

  async verifyPageLoaded(): Promise<void> {
    await expect(this.page).toHaveURL("/profile");
    await expect(this.pageHeadingUserProfile).toBeVisible();
  }

  async verifyOnProfilePage(): Promise<void> {
    await expect(this.page).toHaveURL("/profile");
  }

  async verifyOrganizationId(organizationId: string): Promise<void> {
    // Verify the organization ID is visible

    await expect(this.page.getByText(organizationId)).toBeVisible();
  }
}
