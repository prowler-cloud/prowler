import { Page, Locator, expect } from "@playwright/test";
import { BasePage } from "../base-page";

export class InvitationsPage extends BasePage {
  // Page heading
  readonly pageHeadingSendInvitation: Locator;
  readonly pageHeadingInvitations: Locator;

  // UI elements
  readonly sendInviteButton: Locator;
  readonly inviteButton: Locator;
  readonly emailInput: Locator;
  readonly roleSelect: Locator;

  // Invitation details
  readonly reviewInvitationDetailsButton: Locator;
  readonly shareUrl: Locator;

  constructor(page: Page) {
    super(page);

    // Page heading
    this.pageHeadingInvitations = page.getByRole("heading", {
      name: "Invitations",
    });
    this.pageHeadingSendInvitation = page.getByRole("heading", {
      name: "Send Invitation",
    });

    // Button to invite a new user
    this.inviteButton = page.getByRole("link", {
      name: "Send Invitation",
      exact: true,
    });
    this.sendInviteButton = page.getByRole("button", {
      name: "Send Invitation",
      exact: true,
    });

    // Form inputs
    this.emailInput = page.getByRole("textbox", { name: "Email" });

    // Form select
    this.roleSelect = page
      .getByRole("combobox", { name: /Role|Select a role/i })
      .or(page.getByRole("button", { name: /Role|Select a role/i }))
      .first();

    // Form details
    this.reviewInvitationDetailsButton = page.getByRole("button", {
      name: /Review Invitation Details/i,
    });

    // Multiple strategies to find the share URL
    this.shareUrl = page
      .locator(
        'a[href*="/sign-up?invitation_token="], [data-testid="share-url"], .share-url, code, pre',
      )
      .first();
  }

  async goto(): Promise<void> {
    // Navigate to the invitations page

    await super.goto("/invitations");
  }

  async clickSendInviteButton(): Promise<void> {
    // Click the send invitation button

    await this.sendInviteButton.click();
  }

  async clickInviteButton(): Promise<void> {
    // Click the invitation button

    await this.inviteButton.click();
  }

  async verifyPageLoaded(): Promise<void> {
    // Verify the invitations page is loaded

    await expect(this.pageHeadingInvitations).toBeVisible();
  }

  async verifyInvitePageLoaded(): Promise<void> {
    // Verify the invite page is loaded

    await expect(this.emailInput).toBeVisible();
    await expect(this.sendInviteButton).toBeVisible();
  }

  async fillEmail(email: string): Promise<void> {
    // Fill the email input
    await this.emailInput.fill(email);
  }

  async selectRole(role: string): Promise<void> {
    // Select the role option

    // Open the role dropdown
    await expect(this.roleSelect).toBeVisible({ timeout: 15000 });
    await this.roleSelect.click();

    // Prefer ARIA role option inside listbox
    const option = this.page.getByRole("option", {
      name: new RegExp(`^${role}$`, "i"),
    });

    if (await option.count()) {
      await option.first().click();
    } else {
      throw new Error(`Role option ${role} not found`);
    }
    // Ensure a role value was selected in the trigger
    await expect(this.roleSelect).not.toContainText(/Select a role/i);
  }

  async verifyInviteDataPageLoaded(): Promise<void> {
    // Verify the invite data page is loaded

    await expect(this.reviewInvitationDetailsButton).toBeVisible();
  }

  async getShareUrl(): Promise<string> {
    // Get the share url

    // Get the share url text content
    const text = await this.shareUrl.textContent();

    if (!text) {
      throw new Error("Share url not found");
    }
    return text;
  }
}
