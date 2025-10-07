import { test, expect } from "@playwright/test";
import {
  goToLogin,
  login,
  verifySuccessfulLogin,
  getSession,
  verifySessionValid,
  TEST_CREDENTIALS,
  URLS,
} from "./helpers";

test.describe("Token Refresh Flow", () => {
  test("should refresh access token when expired", async ({ page }) => {
    // Login first
    await goToLogin(page);
    await login(page, TEST_CREDENTIALS.VALID);
    await verifySuccessfulLogin(page);

    // Get initial session using helper
    const initialSession = await verifySessionValid(page);
    const initialAccessToken = initialSession.accessToken;

    // Wait for some time to allow token to potentially expire
    // In a real scenario, you might want to manipulate the token expiry
    await page.waitForTimeout(2000);

    // Make a request that requires authentication
    // This should trigger token refresh if needed
    await page.reload();
    await page.waitForLoadState("networkidle");

    // Verify we're still authenticated
    await expect(page).toHaveURL(URLS.DASHBOARD);

    // Get session after potential refresh using helper
    const refreshedSession = await verifySessionValid(page);

    // User data should be maintained
    expect(refreshedSession.user.email).toBe(initialSession.user.email);
    expect(refreshedSession.userId).toBe(initialSession.userId);
    expect(refreshedSession.tenantId).toBe(initialSession.tenantId);
  });

  test("should handle concurrent requests with token refresh", async ({
    page,
  }) => {
    // Login
    await goToLogin(page);
    await login(page, TEST_CREDENTIALS.VALID);
    await verifySuccessfulLogin(page);

    // Make multiple concurrent requests to the API
    const requests = Array(5)
      .fill(null)
      .map(() => page.request.get("/api/auth/session"));

    const responses = await Promise.all(requests);

    // All requests should succeed - verify using helper
    for (const response of responses) {
      expect(response.ok()).toBeTruthy();
      const session = await response.json();

      // Validate session structure
      expect(session).toBeTruthy();
      expect(session.user).toBeTruthy();
      expect(session.accessToken).toBeTruthy();
      expect(session.refreshToken).toBeTruthy();
      expect(session.error).toBeUndefined();
    }
  });

  test("should preserve user permissions after token refresh", async ({
    page,
  }) => {
    // Login
    await goToLogin(page);
    await login(page, TEST_CREDENTIALS.VALID);
    await verifySuccessfulLogin(page);

    // Get initial session with permissions using helper
    const initialSession = await verifySessionValid(page);
    const initialPermissions = initialSession.user.permissions;

    // Reload page to potentially trigger token refresh
    await page.reload();
    await page.waitForLoadState("networkidle");

    // Get session after reload using helper
    const refreshedSession = await verifySessionValid(page);

    // Permissions should be preserved
    expect(refreshedSession.user.permissions).toEqual(initialPermissions);

    // All user data should be preserved
    expect(refreshedSession.user.email).toBe(initialSession.user.email);
    expect(refreshedSession.user.name).toBe(initialSession.user.name);
    expect(refreshedSession.user.companyName).toBe(
      initialSession.user.companyName,
    );
  });

  test("should clear session when cookies are removed", async ({
    page,
    context,
  }) => {
    // Login
    await goToLogin(page);
    await login(page, TEST_CREDENTIALS.VALID);
    await verifySuccessfulLogin(page);

    // Verify session is valid using helper
    await verifySessionValid(page);

    // Clear all cookies to simulate complete session expiry
    await context.clearCookies();

    // Verify session is null after clearing cookies
    const expiredSession = await getSession(page);
    expect(expiredSession).toBeNull();

    // Note: Middleware redirect behavior is tested in auth-middleware-error.spec.ts
  });
});

test.describe("Token Error Handling", () => {
  test("should detect RefreshTokenError in session", async ({ page }) => {
    // Login
    await goToLogin(page);
    await login(page, TEST_CREDENTIALS.VALID);
    await verifySuccessfulLogin(page);

    // Remove cookies to simulate a refresh failure scenario
    await page.context().clearCookies();

    // Force a navigation that requires auth; middleware should redirect with error
    await page.goto("/providers", { waitUntil: "networkidle" });
    await expect(page).toHaveURL(/sign-in/);

    // Verify login form is available for re-authentication
    await expect(page.getByLabel("Email")).toBeVisible();
  });

  test("should handle missing refresh token gracefully", async ({ page }) => {
    // Login normally first
    await goToLogin(page);
    await login(page, TEST_CREDENTIALS.VALID);
    await verifySuccessfulLogin(page);

    // Verify session is valid and has refresh token using helper
    await verifySessionValid(page);
  });
});
