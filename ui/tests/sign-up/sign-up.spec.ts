import { test } from "@playwright/test";
import { SignUpPage } from "./sign-up-page";
import { SignInPage } from "../sign-in/sign-in-page";
import { makeSuffix } from "../helpers";

test.describe("Sign Up Flow", () => {
  test("should register a new user successfully", { tag: ['@critical', '@e2e', '@signup', '@SIGNUP-E2E-001'] }, async ({ page }) => {
    const signUpPage = new SignUpPage(page);
    await signUpPage.goto();

    // Generate unique test data
    const suffix = makeSuffix(10);
    const uniqueEmail = `e2e+${suffix}@prowler.com`;

    // Fill and submit the sign-up form
    await signUpPage.signup({
      name: `E2E User ${suffix}`,
      company: `Test E2E Co ${suffix}`,
      email: uniqueEmail,
      password: "Thisisapassword123@",
      confirmPassword: "Thisisapassword123@",
      acceptTerms: true,
    });
    
    // Verify no errors occurred during sign-up
    await signUpPage.verifyNoErrors();
    
    // Verify redirect to login page (OSS environment)
    await signUpPage.verifyRedirectToLogin();
    
    // Verify the newly created user can log in successfully
    const signInPage = new SignInPage(page);
    await signInPage.login({
      email: uniqueEmail,
      password: "Thisisapassword123@",
    });
    await signInPage.verifySuccessfulLogin();
  });
});


