import { Page, Locator, expect } from "@playwright/test";
import { BasePage } from "../base-page";
import { HomePage } from "../home/home-page";

export interface SignInCredentials {
  email: string;
  password: string;
}

export interface SocialAuthConfig {
  googleEnabled: boolean;
  githubEnabled: boolean;
}

export class SignInPage extends BasePage {
  readonly homePage: HomePage;
  
  // Form elements
  readonly emailInput: Locator;
  readonly passwordInput: Locator;
  readonly loginButton: Locator;
  readonly form: Locator;
  
  // Social authentication buttons
  readonly googleButton: Locator;
  readonly githubButton: Locator;
  readonly samlButton: Locator;
  
  // Navigation elements
  readonly signUpLink: Locator;
  readonly backButton: Locator;
  
  // UI elements
  readonly logo: Locator;
  
  // Error messages
  readonly errorMessages: Locator;
  
  // SAML specific elements
  readonly samlModeTitle: Locator;
  readonly samlEmailInput: Locator;

  constructor(page: Page) {
    super(page);
    this.homePage = new HomePage(page);
    
    // Form elements
    this.emailInput = page.getByRole("textbox", { name: "Email" });
    this.passwordInput = page.getByRole("textbox", { name: "Password" });
    this.loginButton = page.getByRole("button", { name: "Log in" });
    this.form = page.locator("form");
    
    // Social authentication buttons
    this.googleButton = page.getByRole("button", { name: "Continue with Google" });
    this.githubButton = page.getByRole("button", { name: "Continue with Github" });
    this.samlButton = page.getByRole("button", { name: "Continue with SAML SSO" });
    
    // Navigation elements
    this.signUpLink = page.getByRole("link", { name: "Sign up" });
    this.backButton = page.getByRole("button", { name: "Back" });
    
    // UI elements
    this.logo = page.locator('svg[width="300"]');
    
    // Error messages
    this.errorMessages = page.locator('[role="alert"], .error-message, [data-testid="error"]');
    
    // SAML specific elements
    this.samlModeTitle = page.getByRole("heading", { name: "Sign in with SAML SSO" });
    this.samlEmailInput = page.getByRole("textbox", { name: "Email" });
  }

  // Navigation methods
  async goto(): Promise<void> {
    await super.goto("/sign-in");
  }

  // Form interaction methods
  async fillEmail(email: string): Promise<void> {
    await this.emailInput.fill(email);
  }

  async fillPassword(password: string): Promise<void> {
    await this.passwordInput.fill(password);
  }

  async fillCredentials(credentials: SignInCredentials): Promise<void> {
    await this.fillEmail(credentials.email);
    await this.fillPassword(credentials.password);
  }

  async submitForm(): Promise<void> {
    await this.loginButton.click();
  }

  async login(credentials: SignInCredentials): Promise<void> {
    await this.fillCredentials(credentials);
    await this.submitForm();
  }

  // Social authentication methods
  async clickGoogleAuth(): Promise<void> {
    await this.googleButton.click();
  }

  async clickGithubAuth(): Promise<void> {
    await this.githubButton.click();
  }

  async clickSamlAuth(): Promise<void> {
    await this.samlButton.click();
  }

  // SAML SSO methods
  async toggleSamlMode(): Promise<void> {
    await this.clickSamlAuth();
  }

  async goBackFromSaml(): Promise<void> {
    await this.backButton.click();
  }

  async fillSamlEmail(email: string): Promise<void> {
    await this.samlEmailInput.fill(email);
  }

  async submitSamlForm(): Promise<void> {
    await this.submitForm();
  }

  // Navigation methods
  async goToSignUp(): Promise<void> {
    await this.signUpLink.click();
  }

  // Validation and assertion methods
  async verifyPageLoaded(): Promise<void> {
    await expect(this.page).toHaveTitle(/Prowler/);
    await expect(this.logo).toBeVisible();
    await expect(this.page.getByRole("heading", { name: "Sign in", exact: true })).toBeVisible();
  }

  async verifyFormElements(): Promise<void> {
    await expect(this.emailInput).toBeVisible();
    await expect(this.passwordInput).toBeVisible();
    await expect(this.loginButton).toBeVisible();
  }

  async verifySocialButtons(config: SocialAuthConfig): Promise<void> {
    if (config.googleEnabled) {
      await expect(this.googleButton).toBeVisible();
    }
    if (config.githubEnabled) {
      await expect(this.githubButton).toBeVisible();
    }
    await expect(this.samlButton).toBeVisible();
  }

  async verifyNavigationLinks(): Promise<void> {
    await expect(this.page.getByRole('link', { name: /Need to create an account\?/i })).toBeVisible();
    await expect(this.signUpLink).toBeVisible();
  }

  async verifySuccessfulLogin(): Promise<void> {
    await this.homePage.verifyPageLoaded();
  }

  async verifyLoginError(errorMessage: string = "Invalid email or password"): Promise<void> {
    await expect(this.page.getByRole("alert", { name: errorMessage })).toBeVisible();
    await expect(this.page).toHaveURL("/sign-in");
  }

  async verifySamlModeActive(): Promise<void> {
    await expect(this.samlModeTitle).toBeVisible();
    await expect(this.passwordInput).not.toBeVisible();
    await expect(this.backButton).toBeVisible();
  }

  async verifyNormalModeActive(): Promise<void> {
    await expect(this.page.getByRole("heading", { name: "Sign in", exact: true })).toBeVisible();
    await expect(this.passwordInput).toBeVisible();
  }

  async verifyLoadingState(): Promise<void> {
    await expect(this.loginButton).toHaveAttribute("aria-disabled", "true");
    await super.verifyLoadingState();
  }

  async verifyFormValidation(): Promise<void> {
    // Check for common validation messages
    const emailError = this.page.getByRole("alert", { name: "Please enter a valid email address." });
    const passwordError = this.page.getByRole("alert", { name: "Password is required." });
    
    // At least one validation error should be visible
    await expect(emailError.or(passwordError)).toBeVisible();
  }

  // Accessibility methods
  async verifyKeyboardNavigation(): Promise<void> {
    // Test tab navigation through form elements
    await this.page.keyboard.press("Tab"); // Theme toggle
    await this.page.keyboard.press("Tab"); // Email field
    await expect(this.emailInput).toBeFocused();

    await this.page.keyboard.press("Tab"); // Password field
    await expect(this.passwordInput).toBeFocused();

    await this.page.keyboard.press("Tab"); // Show password button
    await this.page.keyboard.press("Tab"); // Login button
    await expect(this.loginButton).toBeFocused();
  }

  async verifyAriaLabels(): Promise<void> {
    await expect(this.page.getByRole("textbox", { name: "Email" })).toBeVisible();
    await expect(this.page.getByRole("textbox", { name: "Password" })).toBeVisible();
    await expect(this.page.getByRole("button", { name: "Log in" })).toBeVisible();
  }

  // Utility methods
  async clearForm(): Promise<void> {
    await this.emailInput.clear();
    await this.passwordInput.clear();
  }

  async isFormValid(): Promise<boolean> {
    const emailValue = await this.emailInput.inputValue();
    const passwordValue = await this.passwordInput.inputValue();
    return emailValue.length > 0 && passwordValue.length > 0;
  }

  // Browser interaction methods

  // Session management methods
  async logout(): Promise<void> {
    await this.homePage.signOut();
  }

  async verifyLogoutSuccess(): Promise<void> {
    await expect(this.page).toHaveURL("/sign-in");
    await expect(this.page.getByRole("heading", { name: "Sign in", exact: true })).toBeVisible();
  }

  // Advanced interaction methods
  async fillFormWithValidation(credentials: SignInCredentials): Promise<void> {
    // Fill email first and check for validation
    await this.fillEmail(credentials.email);
    await this.page.keyboard.press("Tab"); // Trigger validation
    
    // Fill password
    await this.fillPassword(credentials.password);
  }

  async submitFormWithEnterKey(): Promise<void> {
    await this.passwordInput.press("Enter");
  }

  async submitFormWithButtonClick(): Promise<void> {
    await this.submitForm();
  }

  // Error handling methods
  async handleSamlError(): Promise<void> {
    const samlError = this.page.getByRole("alert", { name: "SAML Authentication Error" });
    if (await samlError.isVisible()) {
      // Handle SAML error if present
      console.log("SAML authentication error detected");
    }
  }

  // Wait methods
  async waitForFormSubmission(): Promise<void> {
    await this.page.waitForFunction(() => {
      const button = document.querySelector('button[aria-disabled="true"]');
      return button === null;
    });
  }

  async waitForRedirect(expectedUrl: string): Promise<void> {
    await this.page.waitForURL(expectedUrl);
  }
}
