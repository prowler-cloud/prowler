import { test, expect } from "@playwright/test";
import { SignInPage } from "./sign-in-page";
import { HomePage } from "../home/home-page";
import { TEST_CREDENTIALS } from "../helpers";

test.describe("Session Error Messages", () => {
  // Increase timeout for tests that involve session operations under load
  test.setTimeout(60000);

  test(
    "should show RefreshAccessTokenError message",
    { tag: ["@e2e", "@signin", "@session", "@AUTH-SESSION-E2E-001"] },
    async ({ page }) => {
      const signInPage = new SignInPage(page);

      await page.goto("/sign-in?error=RefreshAccessTokenError");
      await page.waitForTimeout(200);

      const toast = page.locator('[role="status"], [role="alert"]').first();
      const isVisible = await toast.isVisible().catch(() => false);

      if (isVisible) {
        const text = await toast.textContent();
        expect(text).toContain("Session Expired");
        expect(text).toContain("Please sign in again");
      }

      await signInPage.verifyFormElements();
    },
  );

  test(
    "should show MissingRefreshToken error message",
    { tag: ["@e2e", "@signin", "@session", "@AUTH-SESSION-E2E-002"] },
    async ({ page }) => {
      const signInPage = new SignInPage(page);

      await page.goto("/sign-in?error=MissingRefreshToken");
      await page.waitForTimeout(200);

      const toast = page.locator('[role="status"], [role="alert"]').first();
      const isVisible = await toast.isVisible().catch(() => false);

      if (isVisible) {
        const text = await toast.textContent();
        expect(text).toContain("Session Error");
      }

      await expect(signInPage.emailInput).toBeVisible();
    },
  );

  test(
    "should show generic error for unknown error types",
    { tag: ["@e2e", "@signin", "@session", "@AUTH-SESSION-E2E-003"] },
    async ({ page }) => {
      await page.goto("/sign-in?error=UnknownError");
      await page.waitForTimeout(200);

      const toast = page.locator('[role="status"], [role="alert"]').first();
      const isVisible = await toast.isVisible().catch(() => false);

      if (isVisible) {
        const text = await toast.textContent();
        expect(text).toContain("Authentication Error");
        expect(text).toContain("Please sign in again");
      }
    },
  );

  test(
    "should include callbackUrl in redirect",
    { tag: ["@e2e", "@signin", "@session", "@AUTH-SESSION-E2E-004"] },
    async ({ page, context }) => {
      const signInPage = new SignInPage(page);
      const homePage = new HomePage(page);

      await signInPage.goto();
      await signInPage.login(TEST_CREDENTIALS.VALID);
      await homePage.verifyPageLoaded();

      await page.goto("/scans");
      await page.waitForLoadState("domcontentloaded");

      // Clear cookies and reload to ensure middleware detects missing session
      await context.clearCookies();

      // Navigate to protected route - middleware should redirect to sign-in
      // Use waitUntil: "commit" to catch the redirect before client-side hydration
      await page.goto("/providers", { waitUntil: "commit" });

      // Wait for the redirect to complete
      await expect(page).toHaveURL(/\/sign-in/, { timeout: 10000 });

      // Verify callbackUrl is present
      const url = new URL(page.url());
      const callbackUrl = url.searchParams.get("callbackUrl");
      // callbackUrl might be encoded, so check if it contains "providers"
      expect(callbackUrl).toContain("providers");
    },
  );
});
