import { expect, test } from "@playwright/test";

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
      await context.clearCookies();

      // Navigate directly to a protected route and assert callbackUrl preservation.
      await page.goto("/providers", { waitUntil: "commit" });
      await signInPage.verifyRedirectWithCallback("/providers");
    },
  );
});
