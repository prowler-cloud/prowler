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
    async ({ page, context, browser }) => {
      const signInPage = new SignInPage(page);
      const providersPage = new ProvidersPage(page);

      await signInPage.loginAndVerify(TEST_CREDENTIALS.VALID);

      await providersPage.goto();
      await providersPage.verifyPageLoaded();

      // Build an isolated context with an explicitly invalid auth token.
      // This avoids races from active tabs rehydrating cookies in the original context.
      const authenticatedState = await context.storageState();
      const authCookies = authenticatedState.cookies.filter((cookie) =>
        /(authjs|next-auth)/i.test(cookie.name),
      );
      expect(authCookies.length).toBeGreaterThan(0);

      const invalidSessionContext = await browser.newContext({
        storageState: {
          origins: authenticatedState.origins,
          cookies: authenticatedState.cookies.map((cookie) =>
            /(authjs|next-auth)/i.test(cookie.name)
              ? { ...cookie, value: "invalid.session.token" }
              : cookie,
          ),
        },
      });

      try {
        // Use a fresh page to force a full navigation through proxy in Next.js 16.
        const freshPage = await invalidSessionContext.newPage();
        const freshSignInPage = new SignInPage(freshPage);
        const cacheBuster = Date.now();
        await freshPage.goto(`/scans?e2e_mw=${cacheBuster}`, {
          waitUntil: "commit",
        });
        await freshSignInPage.verifyRedirectWithCallback("/scans");
      } finally {
        await invalidSessionContext.close();
      }
    },
  );

  // Note: Billing and integrations permission tests removed
  // These features only exist in Prowler Cloud, not in the open-source version
});
