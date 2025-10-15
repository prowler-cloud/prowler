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
  
  // Social login buttons
  readonly githubButton: Locator;

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
    this.termsCheckbox = page.getByText("I agree with the");
    
    // Social login buttons
    this.githubButton = page.getByRole("button", { name: "Continue with Github" });
  }

  async goto(): Promise<void> {
    await super.goto("/sign-up");
  }

  async verifyPageLoaded(): Promise<void> {
    // Verify unique title - only appears on sign-up page
    await expect(this.page.locator('p').getByText("Sign up", { exact: true }).first()).toBeVisible();
    
    // Verify all required form fields are present
    await expect(this.nameInput).toBeVisible();
    await expect(this.emailInput).toBeVisible();
    await expect(this.passwordInput).toBeVisible();
    await expect(this.confirmPasswordInput).toBeVisible();
    
    // Verify primary action button
    await expect(this.submitButton).toBeVisible();
    
    // Verify distinctive separator between form and social login
    await expect(this.page.getByText("OR", { exact: true })).toBeVisible();
    
    // Verify social login options are available (distinctive of sign-up vs other pages)
    await expect(this.page.getByText("Continue with Github")).toBeVisible();
    await expect(this.page.getByText("Continue with Google")).toBeVisible();
    
    // Verify sign-up specific link (different from sign-in page)
    await expect(this.page.getByText("Already have an account?")).toBeVisible();
    await expect(this.loginLink).toBeVisible();
    
    // Verify correct URL
    expect(this.page.url()).toContain('/sign-up');
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

  // Social login methods
  async clickGithubLogin(): Promise<void> {
    await this.githubButton.click();
  }

  async verifyGithubButtonVisible(): Promise<void> {
    await expect(this.githubButton).toBeVisible();
  }

  async verifyGithubButtonEnabled(): Promise<void> {
    await expect(this.githubButton).toBeEnabled();
  }

  async verifyRedirectToGithubOAuth(): Promise<void> {
    // Verify redirect to Github OAuth page
    await expect(this.page).toHaveURL(/github\.com\/login/);
  }

  async verifyGithubOAuthFlow(): Promise<void> {
    // Verify Github OAuth page elements
    await expect(this.page.getByText("Sign in to GitHub")).toBeVisible();
    await expect(this.page.getByText("to continue to Prowler")).toBeVisible();
  }

  async fillGithubCredentials(username: string, password: string): Promise<void> {
    // Fill Github login form based on MCP exploration
    await this.page.getByRole("textbox", { name: "Username or email address" }).fill(username);
    await this.page.getByRole("textbox", { name: "Password" }).fill(password);
  }

  async submitGithubLogin(): Promise<void> {
    // Click Github Sign in button
    await this.page.getByRole("button", { name: "Sign in" }).click();
  }

  async completeGithubOAuth(username: string, password: string): Promise<void> {
    // Complete the Github OAuth flow
    await this.fillGithubCredentials(username, password);
    await this.submitGithubLogin();
  }

  async verifyGithubApplicationInfo(): Promise<void> {
    // Verify Prowler application info is displayed on GitHub OAuth page
    await expect(this.page.locator('img[alt*="Prowler"]')).toBeVisible();
    
    // Verify the OAuth consent message shows Prowler app name
    await expect(this.page.getByText(/to continue to.*Prowler/i)).toBeVisible();
    
    // Verify "Sign in to GitHub" text is present
    await expect(this.page.getByText("Sign in to GitHub")).toBeVisible();
    
    // Verify GitHub OAuth form elements are present
    await expect(this.page.getByRole("textbox", { name: /username or email/i })).toBeVisible();
    await expect(this.page.getByRole("textbox", { name: /password/i })).toBeVisible();
    await expect(this.page.getByRole("button", { name: "Sign in" })).toBeVisible();
  }
}


