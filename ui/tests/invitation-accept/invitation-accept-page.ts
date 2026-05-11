import { expect, Locator, Page } from "@playwright/test";

import { BasePage } from "../base-page";

export class InvitationAcceptPage extends BasePage {
  // Choice screen (unauthenticated user with valid token)
  readonly choiceHeading: Locator;
  readonly choiceDescription: Locator;
  readonly signInButton: Locator;
  readonly createAccountButton: Locator;

  // No-token error screen
  readonly noTokenHeading: Locator;
  readonly noTokenDescription: Locator;
  readonly goToSignInLink: Locator;

  constructor(page: Page) {
    super(page);

    this.choiceHeading = page.getByRole("heading", {
      name: "You've Been Invited",
    });
    this.choiceDescription = page.getByText(/invited to join a tenant/i);
    this.signInButton = page.getByRole("button", {
      name: /I have an account.*Sign in/i,
    });
    this.createAccountButton = page.getByRole("button", {
      name: /I'm new.*Create an account/i,
    });

    this.noTokenHeading = page.getByRole("heading", {
      name: "Invalid Invitation Link",
    });
    this.noTokenDescription = page.getByText(
      /No invitation token was provided/i,
    );
    this.goToSignInLink = page.getByRole("link", { name: "Go to Sign In" });
  }

  async gotoWithToken(token: string): Promise<void> {
    await super.goto(
      `/invitation/accept?invitation_token=${encodeURIComponent(token)}`,
    );
  }

  async gotoWithoutToken(): Promise<void> {
    await super.goto("/invitation/accept");
  }

  async verifyChoiceScreen(): Promise<void> {
    await expect(this.choiceHeading).toBeVisible();
    await expect(this.choiceDescription).toBeVisible();
    await expect(this.signInButton).toBeVisible();
    await expect(this.createAccountButton).toBeVisible();
  }

  async verifyNoTokenScreen(): Promise<void> {
    await expect(this.noTokenHeading).toBeVisible();
    await expect(this.noTokenDescription).toBeVisible();
    await expect(this.goToSignInLink).toBeVisible();
  }
}
