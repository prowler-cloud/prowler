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
    this.emailInput = page.getByLabel("Email");
    this.passwordInput = page.locator('input[name="password"]');
    this.confirmPasswordInput = page.locator('input[name="confirmPassword"]');
    this.invitationTokenInput = page.locator('input[name="invitationToken"]');

    this.submitButton = page.getByRole("button", { name: "Sign up" });
    this.loginLink = page.getByRole("link", { name: "Log in" });
    this.termsCheckbox = page.getByRole("checkbox", { name: /I agree with the/i });
  }

  async goto(): Promise<void> {
    await super.goto("/sign-up");
  }

  async verifyPageLoaded(): Promise<void> {
    await expect(this.page.getByRole("heading", { name: "Sign up" })).toBeVisible();
    await expect(this.emailInput).toBeVisible();
    await expect(this.submitButton).toBeVisible();
    await this.waitForPageLoad();
  }

  async fillName(name: string): Promise<void> {
    await this.nameInput.fill(name);
  }

  async fillCompany(company?: string): Promise<void> {
    if (company) {
      await this.companyInput.fill(company);
    }
  }

  async fillEmail(email: string): Promise<void> {
    await this.emailInput.fill(email);
  }

  async fillPassword(password: string): Promise<void> {
    await this.passwordInput.fill(password);
  }

  async fillConfirmPassword(confirmPassword: string): Promise<void> {
    await this.confirmPasswordInput.fill(confirmPassword);
  }

  async fillInvitationToken(token?: string | null): Promise<void> {
    if (token) {
      await this.invitationTokenInput.fill(token);
    }
  }

  async acceptTermsIfPresent(accept: boolean = true): Promise<void> {
    // Only in cloud env; check presence before interacting
    if (await this.termsCheckbox.isVisible()) {
      if (accept) {
        await this.termsCheckbox.click();
      }
    }
  }

  async submit(): Promise<void> {
    await this.submitButton.click();
  }

  async signup(data: SignUpData): Promise<void> {
    await this.fillName(data.name);
    await this.fillCompany(data.company);
    await this.fillEmail(data.email);
    await this.fillPassword(data.password);
    await this.fillConfirmPassword(data.confirmPassword);
    await this.fillInvitationToken(data.invitationToken ?? undefined);
    await this.acceptTermsIfPresent(data.acceptTerms ?? true);
    await this.submit();
  }

  async verifyRedirectToLogin(): Promise<void> {
    await expect(this.page).toHaveURL("/sign-in");
  }

  async verifyRedirectToEmailVerification(): Promise<void> {
    await expect(this.page).toHaveURL("/email-verification");
  }
}


