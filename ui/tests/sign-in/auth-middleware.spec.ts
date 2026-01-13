import { test, expect } from "@playwright/test";
import { SignInPage } from "./sign-in-page";
import { HomePage } from "../home/home-page";
import { TEST_CREDENTIALS, URLS, verifySessionValid } from "../helpers";

test.describe("Middleware Error Handling", () => {
  // Increase timeout for tests that involve multiple navigations under load
  test.setTimeout(60000);

  test(
    "should allow access to public routes without session",
    { tag: ["@e2e", "@signin", "@middleware", "@AUTH-MW-E2E-001"] },
    async ({ page, context }) => {
      await context.clearCookies();

      await page.goto(URLS.LOGIN);
      await expect(page).toHaveURL(URLS.LOGIN);
      await expect(page.locator("p.text-xl.font-medium")).toHaveText("Sign in");

      await page.goto(URLS.SIGNUP);
      await expect(page).toHaveURL(URLS.SIGNUP);
    },
  );

  test(
    "should maintain protection after session error",
    { tag: ["@e2e", "@signin", "@middleware", "@AUTH-MW-E2E-002"] },
    async ({ page, context }) => {
      const signInPage = new SignInPage(page);
      const homePage = new HomePage(page);

      await signInPage.goto();
      await signInPage.login(TEST_CREDENTIALS.VALID);
      await homePage.verifyPageLoaded();

      await page.goto("/providers");
      await expect(page).toHaveURL("/providers");
      // Wait for the page content to be visible
      await expect(page.locator("main")).toBeVisible();

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

        await page.goto("/scans");
        // With invalid session, should redirect to sign-in
        await expect(page.locator("p.text-xl.font-medium")).toHaveText("Sign in");
      }
    },
  );

  test(
    "should handle permission-based redirects",
    { tag: ["@e2e", "@signin", "@middleware", "@AUTH-MW-E2E-003"] },
    async ({ page }) => {
      const signInPage = new SignInPage(page);
      const homePage = new HomePage(page);

      await signInPage.goto();
      await signInPage.login(TEST_CREDENTIALS.VALID);
      await homePage.verifyPageLoaded();

      const session = await verifySessionValid(page);
      const permissions = session.user.permissions;

      if (!permissions.manage_billing) {
        await page.goto("/billing");
        await expect(page).toHaveURL("/profile");
      }

      if (!permissions.manage_integrations) {
        await page.goto("/integrations");
        await expect(page).toHaveURL("/profile");
      }
    },
  );
});
