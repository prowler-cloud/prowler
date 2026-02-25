import { expect, test } from "@playwright/test";

import { getSessionWithoutCookies, TEST_CREDENTIALS } from "../helpers";
import { ProvidersPage } from "../providers/providers-page";
import { ScansPage } from "../scans/scans-page";
import { SignInPage } from "../sign-in-base/sign-in-base-page";
import { SignUpPage } from "../sign-up/sign-up-page";

test.describe("Middleware Error Handling", () => {
  // Increase timeout for tests that involve multiple navigations under load
  test.setTimeout(60000);

  test(
    "should allow access to public routes without session",
    { tag: ["@e2e", "@auth", "@middleware", "@AUTH-MW-E2E-001"] },
    async ({ page, context }) => {
      const signInPage = new SignInPage(page);
      const signUpPage = new SignUpPage(page);

      await context.clearCookies();

      await signInPage.goto();
      await signInPage.verifyOnSignInPage();

      await signUpPage.goto();
      await signUpPage.verifyPageLoaded();
    },
  );

  test(
    "should maintain protection after session error",
    { tag: ["@e2e", "@auth", "@middleware", "@AUTH-MW-E2E-002"] },
    async ({ page, context }) => {
      const signInPage = new SignInPage(page);
      const providersPage = new ProvidersPage(page);
      const scansPage = new ScansPage(page);

      await signInPage.loginAndVerify(TEST_CREDENTIALS.VALID);

      await providersPage.goto();
      await providersPage.verifyPageLoaded();

      // Remove auth cookies to simulate a broken/expired session deterministically.
      await context.clearCookies();

      const expiredSession = await getSessionWithoutCookies(page);
      expect(expiredSession).toBeNull();

      await scansPage.goto();
      await signInPage.verifyOnSignInPage();
    },
  );

  // Note: Billing and integrations permission tests removed
  // These features only exist in Prowler Cloud, not in the open-source version
});
