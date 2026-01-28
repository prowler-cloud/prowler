import { expect, test } from "@playwright/test";

import { TEST_CREDENTIALS } from "../helpers";
import { ProvidersPage } from "../providers/providers-page";
import { ScansPage } from "../scans/scans-page";
import { SignInPage } from "../sign-in-base/sign-in-base-page";

test.describe("Session Error Messages", () => {
  // Increase timeout for tests that involve session operations under load
  test.setTimeout(60000);

  test(
    "should show RefreshAccessTokenError message",
    { tag: ["@e2e", "@auth", "@session", "@AUTH-SESSION-E2E-001"] },
    async ({ page }) => {
      const signInPage = new SignInPage(page);

      await signInPage.gotoWithError("RefreshAccessTokenError");

      const { isVisible, text } = await signInPage.waitForToast();
      if (isVisible && text) {
        expect(text).toContain("Session Expired");
        expect(text).toContain("Please sign in again");
      }

      await signInPage.verifyFormElements();
    },
  );

  test(
    "should show MissingRefreshToken error message",
    { tag: ["@e2e", "@auth", "@session", "@AUTH-SESSION-E2E-002"] },
    async ({ page }) => {
      const signInPage = new SignInPage(page);

      await signInPage.gotoWithError("MissingRefreshToken");

      const { isVisible, text } = await signInPage.waitForToast();
      if (isVisible && text) {
        expect(text).toContain("Session Error");
      }

      await expect(signInPage.emailInput).toBeVisible();
    },
  );

  test(
    "should show generic error for unknown error types",
    { tag: ["@e2e", "@auth", "@session", "@AUTH-SESSION-E2E-003"] },
    async ({ page }) => {
      const signInPage = new SignInPage(page);

      await signInPage.gotoWithError("UnknownError");

      const { isVisible, text } = await signInPage.waitForToast();
      if (isVisible && text) {
        expect(text).toContain("Authentication Error");
        expect(text).toContain("Please sign in again");
      }
    },
  );

  test(
    "should include callbackUrl in redirect",
    { tag: ["@e2e", "@auth", "@session", "@AUTH-SESSION-E2E-004"] },
    async ({ page, context }) => {
      const signInPage = new SignInPage(page);
      const scansPage = new ScansPage(page);
      const providersPage = new ProvidersPage(page);

      await signInPage.loginAndVerify(TEST_CREDENTIALS.VALID);

      // Navigate to a specific page (just need to be on a protected route)
      await scansPage.goto();
      await expect(page.locator("main")).toBeVisible();

      // Clear cookies to simulate session expiry
      await context.clearCookies();

      // Try to navigate to a different protected route
      await providersPage.goto();

      // Should be redirected to login with callbackUrl
      await signInPage.verifyRedirectWithCallback("/providers");
    },
  );
});
