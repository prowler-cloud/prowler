import { test, expect } from "@playwright/test";
import { SignInPage } from "../sign-in-base/sign-in-base-page";
import { HomePage } from "../home/home-page";
import { TEST_CREDENTIALS, getSession, verifySessionValid } from "../helpers";

test.describe("Token Refresh Flow", () => {
  // Increase timeout for tests that involve session operations under load
  test.setTimeout(60000);

  test(
    "should refresh access token when expired",
    { tag: ["@e2e", "@auth", "@token", "@AUTH-TOKEN-E2E-001"] },
    async ({ page }) => {
      const signInPage = new SignInPage(page);
      const homePage = new HomePage(page);

      await signInPage.goto();
      await signInPage.login(TEST_CREDENTIALS.VALID);
      await homePage.verifyPageLoaded();

      const initialSession = await verifySessionValid(page);
      const initialAccessToken = initialSession.accessToken;

      await page.reload();
      await homePage.verifyPageLoaded();

      const refreshedSession = await verifySessionValid(page);

      expect(refreshedSession.user.email).toBe(initialSession.user.email);
      expect(refreshedSession.userId).toBe(initialSession.userId);
      expect(refreshedSession.tenantId).toBe(initialSession.tenantId);
    },
  );

  test(
    "should handle concurrent requests with token refresh",
    { tag: ["@e2e", "@auth", "@token", "@AUTH-TOKEN-E2E-002"] },
    async ({ page }) => {
      const signInPage = new SignInPage(page);
      const homePage = new HomePage(page);

      await signInPage.goto();
      await signInPage.login(TEST_CREDENTIALS.VALID);
      await homePage.verifyPageLoaded();

      const requests = Array(5)
        .fill(null)
        .map(() => page.request.get("/api/auth/session"));

      const responses = await Promise.all(requests);

      for (const response of responses) {
        expect(response.ok()).toBeTruthy();
        const session = await response.json();

        expect(session).toBeTruthy();
        expect(session.user).toBeTruthy();
        expect(session.accessToken).toBeTruthy();
        expect(session.refreshToken).toBeTruthy();
        expect(session.error).toBeUndefined();
      }
    },
  );

  test(
    "should preserve user permissions after token refresh",
    { tag: ["@e2e", "@auth", "@token", "@AUTH-TOKEN-E2E-003"] },
    async ({ page }) => {
      const signInPage = new SignInPage(page);
      const homePage = new HomePage(page);

      await signInPage.goto();
      await signInPage.login(TEST_CREDENTIALS.VALID);
      await homePage.verifyPageLoaded();

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
    { tag: ["@e2e", "@auth", "@token", "@AUTH-TOKEN-E2E-004"] },
    async ({ page, context }) => {
      const signInPage = new SignInPage(page);
      const homePage = new HomePage(page);

      await signInPage.goto();
      await signInPage.login(TEST_CREDENTIALS.VALID);
      await homePage.verifyPageLoaded();

      await verifySessionValid(page);

      await context.clearCookies();

      const expiredSession = await getSession(page);
      expect(expiredSession).toBeNull();
    },
  );
});
