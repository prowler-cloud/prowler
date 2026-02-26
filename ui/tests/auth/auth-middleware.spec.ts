import { expect, test } from "@playwright/test";

import { TEST_CREDENTIALS } from "../helpers";
import { ProvidersPage } from "../providers/providers-page";
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

      await signInPage.loginAndVerify(TEST_CREDENTIALS.VALID);

      await providersPage.goto();
      await providersPage.verifyPageLoaded();

      // Remove auth cookies to simulate an expired session.
      await context.clearCookies();
      const authCookies = (await context.cookies()).filter((cookie) =>
        /(authjs|next-auth)/i.test(cookie.name),
      );

      if (authCookies.length > 0) {
        await context.addCookies(
          authCookies.map((cookie) => ({
            ...cookie,
            value: "",
            expires: 0,
          })),
        );
      }

      const remainingAuthCookies = (await context.cookies()).filter((cookie) =>
        /(authjs|next-auth)/i.test(cookie.name),
      );
      expect(remainingAuthCookies).toHaveLength(0);

      // Use a new page to avoid in-memory router/cache state from the previous navigation.
      const freshPage = await context.newPage();
      const freshSignInPage = new SignInPage(freshPage);
      const cacheBuster = Date.now();
      await freshPage.goto(`/scans?e2e_mw=${cacheBuster}`, { waitUntil: "commit" });
      await freshSignInPage.verifyOnSignInPage();
    },
  );

  // Note: Billing and integrations permission tests removed
  // These features only exist in Prowler Cloud, not in the open-source version
});
