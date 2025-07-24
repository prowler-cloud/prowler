import { Page, expect } from "@playwright/test";

export const ERROR_MESSAGES = {
  INVALID_CREDENTIALS: "Invalid email or password",
} as const;

export const URLS = {
  LOGIN: "/sign-in",
  SIGNUP: "/sign-up",
  DASHBOARD: "/",
  PROFILE: "/profile",
} as const;

export const TEST_CREDENTIALS = {
  VALID: {
    email: process.env.E2E_USER || "e2e@prowler.com",
    password: process.env.E2E_PASSWORD || "Thisisapassword123@",
  },
  INVALID: {
    email: "invalid@example.com",
    password: "wrongPassword",
  },
  INVALID_EMAIL_FORMAT: {
    email: "invalid-email",
    password: "somepassword",
  },
} as const;

export async function goToLogin(page: Page) {
  await page.goto("/sign-in");
}

export async function goToSignUp(page: Page) {
  await page.goto("/sign-up");
}

export async function fillLoginForm(
  page: Page,
  email: string,
  password: string,
) {
  await page.getByLabel("Email").fill(email);
  await page.getByLabel("Password").fill(password);
}

export async function submitLoginForm(page: Page) {
  await page.getByRole("button", { name: "Log in" }).click();
}

export async function login(
  page: Page,
  credentials: { email: string; password: string } = TEST_CREDENTIALS.VALID,
) {
  await fillLoginForm(page, credentials.email, credentials.password);
  await submitLoginForm(page);
}

export async function verifySuccessfulLogin(page: Page) {
  await expect(page).toHaveURL("/");
  await expect(page.locator("main")).toBeVisible();
  await expect(
    page
      .getByLabel("Breadcrumbs")
      .getByRole("heading", { name: "Overview", exact: true }),
  ).toBeVisible();
}

export async function verifyLoginError(
  page: Page,
  errorMessage = "Invalid email or password",
) {
  await expect(page.getByText(errorMessage)).toBeVisible();
  await expect(page).toHaveURL("/sign-in");
}

export async function toggleSamlMode(page: Page) {
  await page.getByText("Continue with SAML SSO").click();
}

export async function goBackFromSaml(page: Page) {
  await page.getByText("Back").click();
}

export async function verifySamlModeActive(page: Page) {
  await expect(page.getByText("Sign in with SAML SSO")).toBeVisible();
  await expect(page.getByLabel("Password")).not.toBeVisible();
  await expect(page.getByText("Back")).toBeVisible();
}

export async function verifyNormalModeActive(page: Page) {
  await expect(page.getByText("Sign in", { exact: true })).toBeVisible();
  await expect(page.getByLabel("Password")).toBeVisible();
}

export async function logout(page: Page) {
  await page.getByRole("button", { name: "Sign out" }).click();
}

export async function verifyLogoutSuccess(page: Page) {
  await expect(page).toHaveURL("/sign-in");
  await expect(page.getByText("Sign in", { exact: true })).toBeVisible();
}

export async function verifyLoadingState(page: Page) {
  const submitButton = page.getByRole("button", { name: "Log in" });
  await expect(submitButton).toHaveAttribute("aria-disabled", "true");
  await expect(page.getByText("Loading")).toBeVisible();
}

export async function verifyLoginFormElements(page: Page) {
  await expect(page).toHaveTitle(/Prowler/);
  await expect(page.locator('svg[width="300"]')).toBeVisible();

  // Verify form elements
  await expect(page.getByText("Sign in", { exact: true })).toBeVisible();
  await expect(page.getByLabel("Email")).toBeVisible();
  await expect(page.getByLabel("Password")).toBeVisible();
  await expect(page.getByRole("button", { name: "Log in" })).toBeVisible();

  // Verify OAuth buttons
  await expect(page.getByText("Continue with Google")).toBeVisible();
  await expect(page.getByText("Continue with Github")).toBeVisible();
  await expect(page.getByText("Continue with SAML SSO")).toBeVisible();

  // Verify navigation links
  await expect(page.getByText("Need to create an account?")).toBeVisible();
  await expect(page.getByRole("link", { name: "Sign up" })).toBeVisible();
}

export async function waitForPageLoad(page: Page) {
  await page.waitForLoadState("networkidle");
}

export async function verifyDashboardRoute(page: Page) {
  await expect(page).toHaveURL("/");
}
