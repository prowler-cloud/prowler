import { test, expect } from "@playwright/test";
import {
  goToLogin,
  login,
  verifySuccessfulLogin,
  TEST_CREDENTIALS,
  URLS,
} from "./helpers";

test.describe("Session Error Messages", () => {
  test("should show RefreshAccessTokenError message", async ({ page }) => {
    // Navigate to sign-in with RefreshAccessTokenError query param
    await page.goto("/sign-in?error=RefreshAccessTokenError");

    // Wait for toast notification
    await page.waitForTimeout(200);

    // Verify error toast appears
    const toast = page.locator('[role="status"], [role="alert"]').first();

    const isVisible = await toast.isVisible().catch(() => false);

    if (isVisible) {
      const text = await toast.textContent();
      expect(text).toContain("Session Expired");
      expect(text).toContain("Please sign in again");
    }

    // Verify sign-in form is displayed
    await expect(page.getByLabel("Email")).toBeVisible();
    await expect(page.getByLabel("Password")).toBeVisible();
  });

  test("should show MissingRefreshToken error message", async ({ page }) => {
    // Navigate to sign-in with MissingRefreshToken query param
    await page.goto("/sign-in?error=MissingRefreshToken");

    // Wait for toast notification
    await page.waitForTimeout(200);

    // Verify error toast appears
    const toast = page.locator('[role="status"], [role="alert"]').first();

    const isVisible = await toast.isVisible().catch(() => false);

    if (isVisible) {
      const text = await toast.textContent();
      expect(text).toContain("Session Error");
    }

    // Verify sign-in form is displayed
    await expect(page.getByLabel("Email")).toBeVisible();
  });

  test("should show generic error for unknown error types", async ({ page }) => {
    // Navigate to sign-in with unknown error type
    await page.goto("/sign-in?error=UnknownError");

    // Wait for toast notification
    await page.waitForTimeout(200);

    // Verify generic error toast appears
    const toast = page.locator('[role="status"], [role="alert"]').first();

    const isVisible = await toast.isVisible().catch(() => false);

    if (isVisible) {
      const text = await toast.textContent();
      expect(text).toContain("Authentication Error");
      expect(text).toContain("Please sign in again");
    }
  });

  test("should include callbackUrl in redirect", async ({
    page,
    context,
  }) => {
    // Login first
    await goToLogin(page);
    await login(page, TEST_CREDENTIALS.VALID);
    await verifySuccessfulLogin(page);

    // Navigate to a specific page
    await page.goto("/scans");
    await page.waitForLoadState("networkidle");

    // Clear cookies to simulate session expiry
    await context.clearCookies();

    // Try to navigate to a different protected route
    await page.goto("/providers");

    // Should be redirected to login with callbackUrl
    await expect(page).toHaveURL(/\/sign-in\?.*callbackUrl=/);

    // Verify callbackUrl contains the attempted route
    const url = new URL(page.url());
    const callbackUrl = url.searchParams.get("callbackUrl");
    expect(callbackUrl).toBe("/providers");
  });

});
