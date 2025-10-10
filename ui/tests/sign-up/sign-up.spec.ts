import { test } from "@playwright/test";
import { SignUpPage } from "./sign-up-page";
import { SignInPage } from "../sign-in/sign-in-page";
import { makeSuffix } from "../helpers";

test.describe("Sign Up Flow", () => {
  test("should register a new user successfully", { tag: ['@critical', '@e2e', '@signup', '@SIGNUP-E2E-001'] }, async ({ page }) => {
    // Initialize page objects for sign-up and sign-in flows
    const signUpPage = new SignUpPage(page);
    await signUpPage.goto();

    // Generate unique test data to avoid conflicts with existing users
    // Create a base36 random suffix of exactly 10 characters for uniqueness
    const suffix = makeSuffix(10);
    const uniqueEmail = `e2e+${suffix}@prowler.com`;

    // Fill and submit the sign-up form with valid test data
    // Name is exactly 19 characters to meet the max length requirement (20 chars)
    await signUpPage.signup({
      name: `E2E User ${suffix}`, // 9 chars + 10 chars = 19 chars
      company: `Test E2E Co ${suffix}`,
      email: uniqueEmail,
      password: "Thisisapassword123@",
      confirmPassword: "Thisisapassword123@",
      acceptTerms: true,
    });
    
    // Verify successful sign-up redirects to login page (OSS environment)
    await signUpPage.verifyRedirectToLogin();
    
    // Verify the newly created user can successfully log in
    // This ensures the user account was properly created and is functional
    const signInPage = new SignInPage(page);
    await signInPage.login({
      email: uniqueEmail,
      password: "Thisisapassword123@",
    });
    await signInPage.verifySuccessfulLogin();
  });
});


