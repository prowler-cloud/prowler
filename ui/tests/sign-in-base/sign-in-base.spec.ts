import { expect, test } from "@playwright/test";

import { ERROR_MESSAGES, getSession, TEST_CREDENTIALS, URLS } from "../helpers";
import { HomePage } from "../home/home-page";
import { SignUpPage } from "../sign-up/sign-up-page";
import { SignInPage } from "./sign-in-base-page";

test.describe("Login Flow", () => {
  let signInPage: SignInPage;

  test.beforeEach(async ({ page }) => {
    signInPage = new SignInPage(page);
    await signInPage.goto();
  });

  test(
    "should display login form elements",
    { tag: ["@e2e", "@sign-in-base", "@SIGN-IN-BASE-E2E-001"] },
    async () => {
      await signInPage.verifyPageLoaded();
      await signInPage.verifyFormElements();
      await signInPage.verifySocialButtons({
        googleEnabled: true,
        githubEnabled: true,
      });
      await signInPage.verifyNavigationLinks();
    },
  );

  test(
    "should successfully login with valid credentials",
    { tag: ["@critical", "@e2e", "@sign-in-base", "@SIGN-IN-BASE-E2E-002"] },
    async () => {
      await signInPage.login(TEST_CREDENTIALS.VALID);
      await signInPage.verifySuccessfulLogin();
    },
  );

  test(
    "should show error message with invalid credentials",
    { tag: ["@e2e", "@sign-in-base", "@SIGN-IN-BASE-E2E-003"] },
    async () => {
      await signInPage.login(TEST_CREDENTIALS.INVALID);
      await signInPage.verifyLoginError(ERROR_MESSAGES.INVALID_CREDENTIALS);
    },
  );

  test(
    "should handle empty form submission",
    { tag: ["@e2e", "@sign-in-base", "@SIGN-IN-BASE-E2E-004"] },
    async () => {
      await signInPage.submitForm();
      await signInPage.verifyFormValidation();
      await signInPage.verifyStaysOnSignInPage();
    },
  );

  test(
    "should validate email format",
    { tag: ["@e2e", "@sign-in-base", "@SIGN-IN-BASE-E2E-005"] },
    async () => {
      await signInPage.login(TEST_CREDENTIALS.INVALID_EMAIL_FORMAT);
      await signInPage.verifyFormValidation();
      await signInPage.verifyStaysOnSignInPage();
    },
  );

  test(
    "should require password when email is filled",
    { tag: ["@e2e", "@sign-in-base", "@SIGN-IN-BASE-E2E-006"] },
    async () => {
      await signInPage.fillEmail(TEST_CREDENTIALS.VALID.email);
      await signInPage.submitForm();
      await expect(
        signInPage.page.getByText(ERROR_MESSAGES.PASSWORD_REQUIRED),
      ).toBeVisible();
      await signInPage.verifyStaysOnSignInPage();
    },
  );

  test(
    "should toggle SAML SSO mode",
    { tag: ["@e2e", "@sign-in-base", "@SIGN-IN-BASE-E2E-007"] },
    async () => {
      await signInPage.toggleSamlMode();
      await signInPage.verifySamlModeActive();
      await signInPage.goBackFromSaml();
      await signInPage.verifyNormalModeActive();
    },
  );

  test(
    "should show loading state during form submission",
    { tag: ["@e2e", "@sign-in-base", "@SIGN-IN-BASE-E2E-008"] },
    async () => {
      await signInPage.fillCredentials(TEST_CREDENTIALS.VALID);
      await signInPage.submitForm();
      await signInPage.verifyLoadingState();
    },
  );

  test(
    "should handle SAML authentication flow",
    { tag: ["@e2e", "@sign-in-base", "@SIGN-IN-BASE-E2E-009"] },
    async () => {
      const samlEmail = "user@saml-domain.com";
      await signInPage.toggleSamlMode();
      await signInPage.fillSamlEmail(samlEmail);
      await signInPage.submitSamlForm();
      // Note: In a real scenario, this would redirect to IdP
    },
  );
});

test.describe("Session Persistence", () => {
  test(
    "should maintain session after browser refresh",
    { tag: ["@critical", "@e2e", "@sign-in-base", "@SIGN-IN-BASE-E2E-010"] },
    async ({ page }) => {
      const signInPage = new SignInPage(page);
      const homePage = new HomePage(page);

      await signInPage.loginAndVerify(TEST_CREDENTIALS.VALID);

      await page.reload();
      await homePage.verifyPageLoaded();
      await signInPage.verifyNotOnSignInPage();
    },
  );

  test(
    "should redirect to login when accessing protected route without session",
    { tag: ["@e2e", "@sign-in-base", "@SIGN-IN-BASE-E2E-011"] },
    async ({ page }) => {
      const homePage = new HomePage(page);
      const signInPage = new SignInPage(page);

      await homePage.goto();
      await signInPage.verifyOnSignInPage();
    },
  );

  test(
    "should logout successfully",
    { tag: ["@critical", "@e2e", "@sign-in-base", "@SIGN-IN-BASE-E2E-012"] },
    async ({ page }) => {
      const signInPage = new SignInPage(page);
      const homePage = new HomePage(page);

      await signInPage.loginAndVerify(TEST_CREDENTIALS.VALID);

      await homePage.signOut();
      await signInPage.verifyLogoutSuccess();

      await homePage.goto();
      await signInPage.verifyOnSignInPage();
    },
  );

  test(
    "should handle session timeout gracefully",
    { tag: ["@e2e", "@sign-in-base", "@SIGN-IN-BASE-E2E-013"] },
    async ({ browser }) => {
      const authContext = await browser.newContext();
      const authPage = await authContext.newPage();

      const signInPage = new SignInPage(authPage);
      await signInPage.loginAndVerify(TEST_CREDENTIALS.VALID);

      const authSession = await getSession(authPage);
      expect(authSession).toBeTruthy();
      expect(authSession.user).toBeTruthy();

      const unauthContext = await browser.newContext();
      const unauthPage = await unauthContext.newPage();
      const unauthSignInPage = new SignInPage(unauthPage);

      await unauthPage.goto(URLS.PROFILE);
      await unauthSignInPage.verifyOnSignInPage();

      const unauthSession = await getSession(unauthPage);
      expect(unauthSession).toBeNull();

      await authPage.close();
      await authContext.close();
      await unauthPage.close();
      await unauthContext.close();
    },
  );
});

test.describe("Navigation", () => {
  test(
    "should navigate to sign up page",
    { tag: ["@e2e", "@sign-in-base", "@SIGN-IN-BASE-E2E-014"] },
    async ({ page }) => {
      const signInPage = new SignInPage(page);
      const signUpPage = new SignUpPage(page);

      await signInPage.goto();
      await signInPage.goToSignUp();
      await signUpPage.verifyOnSignUpPage();
    },
  );

  test(
    "should navigate from sign up back to sign in",
    { tag: ["@e2e", "@sign-in-base", "@SIGN-IN-BASE-E2E-015"] },
    async ({ page }) => {
      const signInPage = new SignInPage(page);
      const signUpPage = new SignUpPage(page);

      await signUpPage.goto();
      await signUpPage.loginLink.click();
      await signInPage.verifyOnSignInPage();
    },
  );

  test(
    "should handle browser back button correctly",
    { tag: ["@e2e", "@sign-in-base", "@SIGN-IN-BASE-E2E-016"] },
    async ({ page }) => {
      const signInPage = new SignInPage(page);
      const signUpPage = new SignUpPage(page);

      await signInPage.goto();
      await signInPage.goToSignUp();
      await signUpPage.verifyOnSignUpPage();
      await page.goBack();
      await signInPage.verifyOnSignInPage();
    },
  );
});

test.describe("Accessibility", () => {
  let signInPage: SignInPage;

  test.beforeEach(async ({ page }) => {
    signInPage = new SignInPage(page);
    await signInPage.goto();
  });

  test(
    "should be navigable with keyboard",
    {
      tag: ["@e2e", "@sign-in-base", "@accessibility", "@SIGN-IN-BASE-E2E-017"],
    },
    async () => {
      await signInPage.verifyKeyboardNavigation();
    },
  );

  test(
    "should have proper ARIA labels",
    {
      tag: ["@e2e", "@sign-in-base", "@accessibility", "@SIGN-IN-BASE-E2E-018"],
    },
    async () => {
      await signInPage.verifyAriaLabels();
    },
  );
});
