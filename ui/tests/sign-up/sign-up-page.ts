import { Page, Locator, expect } from "@playwright/test";
import { BasePage } from "../base-page";

export interface SignUpData {
  name: string;
  email: string;
  password: string;
  confirmPassword: string;
  company?: string;
  invitationToken?: string | null;
  acceptTerms?: boolean;
}

export class SignUpPage extends BasePage {

  // Form inputs
  readonly nameInput: Locator;
  readonly companyInput: Locator;
  readonly emailInput: Locator;
  readonly passwordInput: Locator;
  readonly confirmPasswordInput: Locator;
  readonly invitationTokenInput: Locator;

  // UI elements
  readonly submitButton: Locator;
  readonly loginLink: Locator;
  readonly termsCheckbox: Locator;

  constructor(page: Page) {
    super(page);

    // Prefer stable name attributes to avoid label ambiguity in composed inputs
    this.nameInput = page.locator('input[name="name"]');
    this.companyInput = page.locator('input[name="company"]');
    this.emailInput = page.getByRole("textbox", { name: "Email" });
    this.passwordInput = page.locator('input[name="password"]');
    this.confirmPasswordInput = page.locator('input[name="confirmPassword"]');
    this.invitationTokenInput = page.locator('input[name="invitationToken"]');

    this.submitButton = page.getByRole("button", { name: "Sign up" });
    this.loginLink = page.getByRole("link", { name: "Log in" });
    this.termsCheckbox = page.getByRole("checkbox", { name: /I agree with the/i });
  }

  async goto(): Promise<void> {
    // Navigate to the sign up page

    await super.goto("/sign-up");
  }
  async gotoInvite(shareUrl: string): Promise<void> {
    // Navigate to the share url

    await  super.goto(shareUrl);
  }

  async verifyPageLoaded(): Promise<void> {
    await expect(this.page).toHaveURL("/sign-up");
    await expect(this.emailInput).toBeVisible();
    await expect(this.submitButton).toBeVisible();
  }

  async verifyOnSignUpPage(): Promise<void> {
    await expect(this.page).toHaveURL("/sign-up");
    await expect(this.emailInput).toBeVisible();
  }

  async fillName(name: string): Promise<void> {
    // Fill the name input

    await this.nameInput.fill(name);
  }

  async fillCompany(company?: string): Promise<void> {
    // Fill the company input

    if (company) {
      await this.companyInput.fill(company);
    }
  }

  async fillEmail(email: string): Promise<void> {
    // Fill the email input

    await this.emailInput.fill(email);
  }

  async fillPassword(password: string): Promise<void> {
    // Fill the password input

    await this.passwordInput.fill(password);
  }

  async fillConfirmPassword(confirmPassword: string): Promise<void> {
    // Fill the confirm password input

    await this.confirmPasswordInput.fill(confirmPassword);
  }

  async fillInvitationToken(token?: string | null): Promise<void> {
    // Fill the invitation token input

    if (token) {
      await this.invitationTokenInput.fill(token);
    }
  }

  async acceptTermsIfPresent(accept: boolean = true): Promise<void> {
    // Accept the terms and conditions if present

    if (await this.termsCheckbox.isVisible()) {
      if (accept) {
        await this.termsCheckbox.click();
      }
    }
  }

  async submit(): Promise<void> {
    // Submit the sign up form

    await this.submitButton.click();
  }

  async signup(data: SignUpData): Promise<void> {
    // Fill the sign up form

    await this.fillName(data.name);
    await this.fillCompany(data.company ?? undefined);
    await this.fillEmail(data.email);
    await this.fillPassword(data.password);
    await this.fillConfirmPassword(data.confirmPassword);
    await this.acceptTermsIfPresent(data.acceptTerms ?? true);
    await this.submit();
  }

  async verifyRedirectToLogin(): Promise<void> {
    // Verify redirect to login page

    await expect(this.page).toHaveURL("/sign-in");
  }

  async verifyRedirectToEmailVerification(): Promise<void> {
    // Verify redirect to email verification page

    await expect(this.page).toHaveURL("/email-verification");
  }
}
