import { expect, test } from "@playwright/test";

import { getSession, TEST_CREDENTIALS, verifySessionValid } from "../helpers";
import { HomePage } from "../home/home-page";
import { SignInPage } from "../sign-in-base/sign-in-base-page";

// Note: HomePage is still needed for verifyPageLoaded after reload in some tests

test.describe("Token Refresh Flow", () => {
  // Increase timeout for tests that involve session operations under load
  test.setTimeout(60000);

  test(
    "should refresh access token when expired",
    { tag: ["@e2e", "@auth", "@token", "@AUTH-TOKEN-E2E-001"] },
    async ({ page }) => {
      const signInPage = new SignInPage(page);
      const homePage = new HomePage(page);

      await signInPage.loginAndVerify(TEST_CREDENTIALS.VALID);

      const initialSession = await verifySessionValid(page);

      await page.reload();
      await homePage.verifyPageLoaded();

      const refreshedSession = await verifySessionValid(page);

      expect(refreshedSession.user.email).toBe(initialSession.user.email);
      expect(refreshedSession.userId).toBe(initialSession.userId);
      expect(refreshedSession.tenantId).toBe(initialSession.tenantId);
    },
  );

  test(
    "should preserve user permissions after token refresh",
    { tag: ["@e2e", "@auth", "@token", "@AUTH-TOKEN-E2E-002"] },
    async ({ page }) => {
      const signInPage = new SignInPage(page);
      const homePage = new HomePage(page);

      await signInPage.loginAndVerify(TEST_CREDENTIALS.VALID);

      const initialSession = await verifySessionValid(page);
      const initialPermissions = initialSession.user.permissions;

      await page.reload();
      await homePage.verifyPageLoaded();

      const refreshedSession = await verifySessionValid(page);

      expect(refreshedSession.user.permissions).toEqual(initialPermissions);

      expect(refreshedSession.user.email).toBe(initialSession.user.email);
      expect(refreshedSession.user.name).toBe(initialSession.user.name);
      expect(refreshedSession.user.companyName).toBe(
        initialSession.user.companyName,
      );
    },
  );

  test(
    "should clear session when cookies are removed",
    { tag: ["@e2e", "@auth", "@token", "@AUTH-TOKEN-E2E-003"] },
    async ({ page, context }) => {
      const signInPage = new SignInPage(page);

      await signInPage.loginAndVerify(TEST_CREDENTIALS.VALID);

      await verifySessionValid(page);

      await context.clearCookies();

      const expiredSession = await getSession(page);
      expect(expiredSession).toBeNull();
    },
  );
});
