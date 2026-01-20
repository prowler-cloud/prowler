import { test, expect } from "@playwright/test";
import { SignInPage } from "../sign-in-base/sign-in-base-page";
import { SignUpPage } from "../sign-up/sign-up-page";
import { HomePage } from "../home/home-page";
import { ProvidersPage } from "../providers/providers-page";
import { ScansPage } from "../scans/scans-page";
import { TEST_CREDENTIALS } from "../helpers";

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
      const homePage = new HomePage(page);
      const providersPage = new ProvidersPage(page);
      const scansPage = new ScansPage(page);

      await signInPage.goto();
      await signInPage.login(TEST_CREDENTIALS.VALID);
      await homePage.verifyPageLoaded();

      await providersPage.goto();
      await providersPage.verifyPageLoaded();

      const cookies = await context.cookies();
      const sessionCookie = cookies.find((c) =>
        c.name.includes("authjs.session-token"),
      );

      if (sessionCookie) {
        await context.clearCookies();
        await context.addCookies([
          {
            ...sessionCookie,
            value: "invalid-session-token",
          },
        ]);

        await scansPage.goto();
        // With invalid session, should redirect to sign-in
        await signInPage.verifyOnSignInPage();
      }
    },
  );

  // Note: Billing and integrations permission tests removed
  // These features only exist in Prowler Cloud, not in the open-source version
});
