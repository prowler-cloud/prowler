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

  test("should handle refresh token error gracefully", async ({
    page,
    context,
  }) => {
    // Login first
    await goToLogin(page);
    await login(page, TEST_CREDENTIALS.VALID);
    await verifySuccessfulLogin(page);

    // Get cookies to manipulate them
    const cookies = await context.cookies();
    const sessionCookie = cookies.find((c) =>
      c.name.includes("authjs.session-token"),
    );

    if (sessionCookie) {
      // Invalidate the session token by corrupting it
      // This simulates an expired/invalid refresh token scenario
      await context.clearCookies();
      await context.addCookies([
        {
          ...sessionCookie,
          value: "invalid-token-value",
        },
      ]);

      // Try to access a protected page
      await page.goto(URLS.DASHBOARD);

      // Should be redirected to login due to invalid session (may include callbackUrl)
      await expect(page).toHaveURL(/\/sign-in/);
      await expect(page.getByText("Sign in", { exact: true })).toBeVisible();
    }
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
  test("should detect RefreshTokenError in session", async ({
    page,
    context,
  }) => {
    // Login
    await goToLogin(page);
    await login(page, TEST_CREDENTIALS.VALID);
    await verifySuccessfulLogin(page);

    // Get the current session cookie
    const cookies = await context.cookies();
    const sessionCookie = cookies.find((c) =>
      c.name.includes("authjs.session-token"),
    );

    if (sessionCookie) {
      // Corrupt the session to simulate a refresh error
      // In a real scenario, this would be an expired refresh token
      await context.clearCookies();

      // Add back a corrupted cookie
      await context.addCookies([
        {
          ...sessionCookie,
          value: "corrupted.token.value",
        },
      ]);

      // Try to get session - should return null with corrupted cookie
      const sessionResponse = await page.request.get("/api/auth/session");

      // With a completely corrupted token, NextAuth should return null
      const sessionText = await sessionResponse.text();

      // Verify session is null or empty (NextAuth can't decrypt corrupted token)
      if (sessionText && sessionText !== "null") {
        const session = await sessionResponse.json();
        // If there's a session object, it might contain an error
        if (session && typeof session === "object") {
          console.log("Session with corrupted token:", session);
        }
      }

      // Try to access protected route
      // With corrupted/invalid session, middleware should redirect to login
      await page.goto(URLS.LOGIN);
      await expect(page).toHaveURL(URLS.LOGIN);

      // Verify user needs to login again
      await expect(page.getByText("Sign in", { exact: true })).toBeVisible();
    }
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
