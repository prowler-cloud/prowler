import { test, expect } from "@playwright/test";
import {
  goToLogin,
  goToSignUp,
  fillLoginForm,
  submitLoginForm,
  login,
  verifySuccessfulLogin,
  verifyLoginError,
  verifyLoginFormElements,
  verifyDashboardRoute,
  toggleSamlMode,
  verifySamlModeActive,
  goBackFromSaml,
  verifyNormalModeActive,
  logout,
  verifyLogoutSuccess,
  waitForPageLoad,
  TEST_CREDENTIALS,
  ERROR_MESSAGES,
  URLS,
  verifyLoadingState,
} from "./helpers";

test.describe("Login Flow", () => {
  test.beforeEach(async ({ page }) => {
    await goToLogin(page);
  });

  test("should display login form elements", async ({ page }) => {
    await verifyLoginFormElements(page);
  });

  test("should successfully login with valid credentials", async ({ page }) => {
    await login(page, TEST_CREDENTIALS.VALID);
    await verifySuccessfulLogin(page);
    await verifyDashboardRoute(page);
  });

  test("should show error message with invalid credentials", async ({
    page,
  }) => {
    // Attempt login with invalid credentials
    await login(page, TEST_CREDENTIALS.INVALID);
    await verifyLoginError(page, ERROR_MESSAGES.INVALID_CREDENTIALS);
  });

  test("should handle empty form submission", async ({ page }) => {
    // Submit empty form
    await submitLoginForm(page);
    await verifyLoginError(page, ERROR_MESSAGES.INVALID_EMAILID);
    // Verify we're still on login page
    await expect(page).toHaveURL(URLS.LOGIN);
  });

  test("should validate email format", async ({ page }) => {
    // Attempt login with invalid email format
    await login(page, TEST_CREDENTIALS.INVALID_EMAIL_FORMAT);
    await verifyLoginError(page, ERROR_MESSAGES.INVALID_EMAILID);
    // Verify we're still on login page
    await expect(page).toHaveURL(URLS.LOGIN);
  });

  test("should toggle SAML SSO mode", async ({ page }) => {
    // Toggle to SAML mode
    await toggleSamlMode(page);
    await verifySamlModeActive(page);
    // Toggle back to normal mode
    await goBackFromSaml(page);
    await verifyNormalModeActive(page);
  });

  test("should show loading state during form submission", async ({ page }) => {
    // Fill valid credentials
    await fillLoginForm(
      page,
      TEST_CREDENTIALS.VALID.email,
      TEST_CREDENTIALS.VALID.password,
    );
    // Submit form and verify loading state
    await submitLoginForm(page);
    // Verify loading state
    await verifyLoadingState(page);
  });

  test("should handle SAML authentication flow", async ({ page }) => {
    // Enter email for SAML
    const samlEmail = "user@saml-domain.com";
    // Toggle to SAML mode
    await toggleSamlMode(page);
    // Fill email (password should be hidden)
    await page.getByLabel("Email").fill(samlEmail);
    // Submit should trigger SAML redirect (we can't test the actual SAML flow in E2E)
    // but we can verify the form submission
    await submitLoginForm(page);

    // Note: In a real scenario, this would redirect to IdP
    // For testing, we just verify the form was submitted
  });
});

test.describe("Session Persistence", () => {
  test("should maintain session after browser refresh", async ({ page }) => {
    // Login first
    await goToLogin(page);
    await login(page, TEST_CREDENTIALS.VALID);
    await verifySuccessfulLogin(page);
    // Refresh the page
    await page.reload();
    await waitForPageLoad(page);
    // Verify session is maintained
    await expect(page).toHaveURL(URLS.DASHBOARD);
    await verifyDashboardRoute(page);
    // Verify user is not redirected back to login
    await expect(page).not.toHaveURL(URLS.LOGIN);
  });

  test("should redirect to login when accessing protected route without session", async ({
    page,
  }) => {
    // Try to access protected route without login
    await page.goto(URLS.DASHBOARD);
    // Should be redirected to login page
    await expect(page).toHaveURL(URLS.LOGIN);
    await expect(page.getByText("Sign in", { exact: true })).toBeVisible();
  });

  test("should logout successfully", async ({ page }) => {
    // Login first
    await goToLogin(page);
    await login(page, TEST_CREDENTIALS.VALID);
    await verifySuccessfulLogin(page);
    // Logout
    await logout(page);
    await verifyLogoutSuccess(page);
    // Verify cannot access protected route after logout
    await page.goto(URLS.DASHBOARD);
    await expect(page).toHaveURL(URLS.LOGIN);
  });

  test("should handle session timeout gracefully", async ({ page }) => {
    // Login first
    await goToLogin(page);
    await login(page, TEST_CREDENTIALS.VALID);
    await verifySuccessfulLogin(page);
    // Simulate session timeout by clearing cookies
    await page.context().clearCookies();
    // Try to navigate to a protected route
    await page.goto(URLS.PROFILE);
    // Should be redirected to login
    await expect(page).toHaveURL(URLS.LOGIN);
  });
});

test.describe("Navigation", () => {
  test("should navigate to sign up page", async ({ page }) => {
    await goToLogin(page);
    await page.getByRole("link", { name: "Sign up" }).click();
    await expect(page).toHaveURL(URLS.SIGNUP);
  });

  test("should navigate from sign up back to sign in", async ({ page }) => {
    await goToSignUp(page);
    await page.getByRole("link", { name: "Log in" }).click();
    await expect(page).toHaveURL(URLS.LOGIN);
    await expect(page.getByText("Sign in", { exact: true })).toBeVisible();
  });

  test("should handle browser back button correctly", async ({ page }) => {
    await goToLogin(page);
    await page.getByRole("link", { name: "Sign up" }).click();
    await expect(page).toHaveURL(URLS.SIGNUP);
    await page.goBack();
    await expect(page).toHaveURL(URLS.LOGIN);
    await expect(page.getByText("Sign in", { exact: true })).toBeVisible();
  });
});

test.describe("Accessibility", () => {
  test.beforeEach(async ({ page }) => {
    await goToLogin(page);
  });

  test("should be navigable with keyboard", async ({ page }) => {
    // Tab through form elements
    await page.keyboard.press("Tab"); // Toggle theme
    await page.keyboard.press("Tab"); // Email field
    await expect(page.getByLabel("Email")).toBeFocused();

    await page.keyboard.press("Tab"); // Password field
    await expect(page.getByLabel("Password")).toBeFocused();

    await page.keyboard.press("Tab"); // Show password button
    await page.keyboard.press("Tab"); // Login button

    if (process.env.NEXT_PUBLIC_IS_CLOUD_ENV === "true") {
      await page.keyboard.press("Tab"); // Forgot password
    }

    await expect(page.getByRole("button", { name: "Log in" })).toBeFocused();
  });

  test("should have proper ARIA labels", async ({ page }) => {
    await expect(page.getByRole("textbox", { name: "Email" })).toBeVisible();
    await expect(page.getByRole("textbox", { name: "Password" })).toBeVisible();
    await expect(page.getByRole("button", { name: "Log in" })).toBeVisible();
  });
});
