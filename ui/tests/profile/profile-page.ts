import { Page, Locator, expect } from "@playwright/test";
import { BasePage } from "../base-page";


export class UserProfilePage extends BasePage {
  
  // Page heading
  readonly pageHeadingUserProfile: Locator;

  constructor(page: Page) {
    super(page);

    // Page heading
    this.pageHeadingUserProfile = page.getByRole("heading", { name: "User Profile" });

  }

  async goto(): Promise<void> {
    // Navigate to the user profile page
    
    await super.goto("/profile");
  }

  async verifyOrganizationId(organizationId: string): Promise<void> {
    // Verify the organization ID is visible

    await expect(this.page.getByText(organizationId)).toBeVisible();
    if (await this.page.getByText(organizationId).count() === 0) {
      throw new Error(`Organization ID ${organizationId} not found`);
    }
  }
}
