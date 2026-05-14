import { expect, Locator, Page } from "@playwright/test";

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
  readonly pageTitle: Locator;

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
    this.googleButton = page.getByRole("button", {
      name: "Continue with Google",
    });
    this.githubButton = page.getByRole("button", {
      name: "Continue with Github",
    });
    this.samlButton = page.getByRole("button", {
      name: "Continue with SAML SSO",
    });

    // Navigation elements
    this.signUpLink = page.getByRole("link", { name: "Sign up" });
    this.backButton = page.getByRole("button", { name: "Back" });

    // UI elements - title is a <p> element, not a heading
    this.logo = page.locator('svg[width="300"]');
    // Use text matching with exact=true to avoid matching other elements
    this.pageTitle = page.getByText("Sign in", { exact: true });

    // Error messages - form validation errors appear as <p> with specific classes
    this.errorMessages = page.locator(
      "p.text-destructive, p.text-sm.text-destructive",
    );

    // SAML specific elements - use text matching
    this.samlModeTitle = page.getByText("Sign in with SAML SSO", {
      exact: true,
    });
    this.samlEmailInput = page.getByRole("textbox", { name: "Email" });
  }

  // Navigation methods
  async goto(): Promise<void> {
    await super.goto("/sign-in");
  }

  /**
   * Navigate to sign-in page with an error query parameter
   * Used for testing error message display (e.g., session expiry)
   */
  async gotoWithError(errorType: string): Promise<void> {
    await this.page.goto(`/sign-in?error=${errorType}`);
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
    await expect(this.pageTitle).toBeVisible();
    await expect(this.pageTitle).toHaveText("Sign in");
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
    await expect(
      this.page.getByText("Need to create an account?"),
    ).toBeVisible();
    await expect(this.signUpLink).toBeVisible();
  }

  async verifySuccessfulLogin(): Promise<void> {
    await this.homePage.verifyPageLoaded();
  }

  /**
   * Complete login flow: navigates to sign-in, logs in, and verifies success.
   * Use this when you need to authenticate from scratch in a test.
   */
  async loginAndVerify(credentials: SignInCredentials): Promise<void> {
    await this.goto();
    await this.login(credentials);
    await this.verifySuccessfulLogin();
  }

  async verifyLoginError(
    errorMessage: string = "Invalid email or password",
  ): Promise<void> {
    // Error messages appear as <p> elements with destructive styling
    await expect(this.page.getByText(errorMessage).first()).toBeVisible();
    await expect(this.page).toHaveURL("/sign-in");
  }

  async verifySamlModeActive(): Promise<void> {
    await expect(this.samlModeTitle).toBeVisible();
    await expect(this.passwordInput).not.toBeVisible();
    await expect(this.backButton).toBeVisible();
  }

  async verifyNormalModeActive(): Promise<void> {
    await expect(this.pageTitle).toHaveText("Sign in");
    await expect(this.passwordInput).toBeVisible();
  }

  async verifyLoadingState(): Promise<void> {
    // Check that button shows loading text or is disabled
    await expect(this.loginButton).toHaveAttribute("aria-disabled", "true");
  }

  async verifyFormValidation(): Promise<void> {
    // Check for common validation messages - they appear as <p> elements
    const emailError = this.page.getByText(
      "Please enter a valid email address.",
    );
    const passwordError = this.page.getByText("Password is required.");

    // At least one validation error should be visible
    await expect(emailError.or(passwordError).first()).toBeVisible();
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
    await expect(
      this.page.getByRole("textbox", { name: "Email" }),
    ).toBeVisible();
    await expect(
      this.page.getByRole("textbox", { name: "Password" }),
    ).toBeVisible();
    await expect(
      this.page.getByRole("button", { name: "Log in" }),
    ).toBeVisible();
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

  // Session management methods
  async logout(): Promise<void> {
    await this.homePage.signOut();
  }

  /**
   * Verifies we are on the sign-in page (URL + title visible)
   * Use this when redirected to sign-in from protected routes
   */
  async verifyOnSignInPage(): Promise<void> {
    await expect(this.page).toHaveURL(/\/sign-in/);
    await expect(this.pageTitle).toBeVisible();
  }

  /**
   * Verifies we stayed on the sign-in page (exact URL match)
   * Use after form validation errors
   */
  async verifyStaysOnSignInPage(): Promise<void> {
    await expect(this.page).toHaveURL("/sign-in");
  }

  /**
   * Verifies we are NOT on the sign-in page
   * Use after successful login to confirm redirect
   */
  async verifyNotOnSignInPage(): Promise<void> {
    await expect(this.page).not.toHaveURL(/\/sign-in/);
  }

  /**
   * Verifies redirect to sign-in includes a callbackUrl parameter
   */
  async verifyRedirectWithCallback(expectedCallback: string): Promise<void> {
    await expect(this.page).toHaveURL(/\/sign-in\?.*callbackUrl=/);
    const url = new URL(this.page.url());
    const callbackUrl = url.searchParams.get("callbackUrl");
    expect(callbackUrl).toBe(expectedCallback);
  }

  /**
   * Wait for toast notification to appear (used for error messages)
   */
  async waitForToast(): Promise<{ isVisible: boolean; text: string | null }> {
    const toast = this.page.locator('[role="status"], [role="alert"]').first();
    try {
      await toast.waitFor({ state: "visible", timeout: 2000 });
      const text = await toast.textContent();
      return { isVisible: true, text };
    } catch {
      return { isVisible: false, text: null };
    }
  }

  async verifyLogoutSuccess(): Promise<void> {
    await this.verifyOnSignInPage();
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
    const samlError = this.page.getByRole("alert", {
      name: "SAML Authentication Error",
    });
    if (await samlError.isVisible()) {
      // SAML error detected - test may need to handle this case
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

  // ===========================================
  // Authentication Setup Methods
  // ===========================================

  /**
   * Authenticate and save the browser state to a file.
   * Used by auth setup projects to create reusable authenticated sessions.
   *
   * @param credentials - User credentials (email and password)
   * @param storagePath - Path to save the authentication state file
   */
  async authenticateAndSaveState(
    credentials: SignInCredentials,
    storagePath: string,
  ): Promise<void> {
    if (!credentials.email || !credentials.password) {
      throw new Error(
        "Email and password are required for authentication and save state",
      );
    }

    await this.loginAndVerify(credentials);
    await this.page.context().storageState({ path: storagePath });
  }
}
