import { test, expect } from "@playwright/test";
import { SignInPage } from "./auth-page";
import { SignUpPage } from "../sign-up/sign-up-page";
import { HomePage } from "../home/home-page";
import { ProvidersPage } from "../providers/providers-page";
import { ScansPage } from "../scans/scans-page";
import { UserProfilePage } from "../profile/profile-page";
import { TEST_CREDENTIALS, verifySessionValid } from "../helpers";

test.describe("Middleware Error Handling", () => {
  // Increase timeout for tests that involve multiple navigations under load
  test.setTimeout(60000);

  test(
    "should allow access to public routes without session",
    { tag: ["@e2e", "@signin", "@middleware", "@AUTH-MW-E2E-001"] },
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
    { tag: ["@e2e", "@signin", "@middleware", "@AUTH-MW-E2E-002"] },
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

  test(
    "should handle permission-based redirects",
    { tag: ["@e2e", "@signin", "@middleware", "@AUTH-MW-E2E-003"] },
    async ({ page }) => {
      const signInPage = new SignInPage(page);
      const homePage = new HomePage(page);
      const profilePage = new UserProfilePage(page);

      await signInPage.goto();
      await signInPage.login(TEST_CREDENTIALS.VALID);
      await homePage.verifyPageLoaded();

      const session = await verifySessionValid(page);
      const permissions = session.user.permissions;

      // Note: /billing and /integrations don't have dedicated Page Objects
      // Using direct navigation since these are permission-redirect tests
      if (!permissions.manage_billing) {
        await page.goto("/billing");
        await profilePage.verifyOnProfilePage();
      }

      if (!permissions.manage_integrations) {
        await page.goto("/integrations");
        await profilePage.verifyOnProfilePage();
      }
    },
  );
});
