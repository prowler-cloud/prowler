import { test, expect } from "@playwright/test";
import {
  goToLogin,
  login,
  verifySuccessfulLogin,
  verifySessionValid,
  TEST_CREDENTIALS,
  URLS,
} from "./helpers";

test.describe("Middleware Error Handling", () => {
  test("should redirect to login when session has error", async ({
    page,
    context,
  }) => {
    // Login first
    await goToLogin(page);
    await login(page, TEST_CREDENTIALS.VALID);
    await verifySuccessfulLogin(page);

    // Verify session is valid using helper
    await verifySessionValid(page);

    // Invalidate the session by clearing cookies
    await context.clearCookies();

    // Try to access a protected route
    await page.goto("/providers", { waitUntil: "networkidle" });

    // Should be redirected to login page by middleware (may include callbackUrl)
    await expect(page).toHaveURL(/\/sign-in/);
    await expect(page.getByText("Sign in", { exact: true })).toBeVisible();
  });

  test("should allow access to public routes without session", async ({
    page,
    context,
  }) => {
    // Ensure no session exists
    await context.clearCookies();

    // Try to access login page (public route)
    await page.goto(URLS.LOGIN);
    await expect(page).toHaveURL(URLS.LOGIN);
    await expect(page.getByText("Sign in", { exact: true })).toBeVisible();

    // Try to access sign-up page (public route)
    await page.goto(URLS.SIGNUP);
    await expect(page).toHaveURL(URLS.SIGNUP);
  });

  test("should maintain protection after session error", async ({
    page,
    context,
  }) => {
    // Login
    await goToLogin(page);
    await login(page, TEST_CREDENTIALS.VALID);
    await verifySuccessfulLogin(page);

    // Navigate to a protected page
    await page.goto("/providers");
    await expect(page).toHaveURL("/providers");

    // Simulate session error by corrupting cookie
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

      // Try to navigate to another protected page
      await page.goto("/scans", { waitUntil: "networkidle" });

      // Should be redirected to login (may include callbackUrl)
      await expect(page).toHaveURL(/\/sign-in/);
    }
  });

  test("should handle permission-based redirects", async ({ page }) => {
    // Login with valid credentials
    await goToLogin(page);
    await login(page, TEST_CREDENTIALS.VALID);
    await verifySuccessfulLogin(page);

    // Get user permissions using helper
    const session = await verifySessionValid(page);
    const permissions = session.user.permissions;

    // Test billing route if user doesn't have permission
    if (!permissions.manage_billing) {
      await page.goto("/billing", { waitUntil: "networkidle" });

      // Should be redirected to profile (as per middleware logic)
      await expect(page).toHaveURL("/profile");
    }

    // Test integrations route if user doesn't have permission
    if (!permissions.manage_integrations) {
      await page.goto("/integrations", { waitUntil: "networkidle" });

      // Should be redirected to profile (as per middleware logic)
      await expect(page).toHaveURL("/profile");
    }
  });

});
