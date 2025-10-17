import { test, expect } from "@playwright/test";
import { SignUpPage } from "./sign-up-page";
import { SignInPage } from "../sign-in/sign-in-page";
import { makeSuffix, TEST_CREDENTIALS } from "../helpers";

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
    
    // Verify redirect to login page
    await signUpPage.verifyRedirectToLogin();
    
    // Verify the newly created user can log in successfully
    const signInPage = new SignInPage(page);
    await signInPage.login({
      email: uniqueEmail,
      password: "Thisisapassword123@",
    });
    await signInPage.verifySuccessfulLogin();
  });

  test("should complete Github OAuth flow for social sign-up", { tag: ['@critical', '@e2e', '@signup', '@social', '@SIGNUP-E2E-002'] }, async ({ page }) => {
    // Verify Github credentials are available
    const githubUsername = process.env.E2E_GITHUB_USER;
    const githubPassword = process.env.E2E_GITHUB_PASSWORD;
    
    if (!githubUsername || !githubPassword) {
      throw new Error('E2E_GITHUB_USER and E2E_GITHUB_PASSWORD environment variables are required for Github OAuth tests');
    }

    const signUpPage = new SignUpPage(page);
    await signUpPage.goto();

    // Verify page loaded correctly
    await signUpPage.verifyPageLoaded();

    // Verify Github social login button is visible and enabled
    await signUpPage.verifyGithubButtonVisible();
    await signUpPage.verifyGithubButtonEnabled();

    // Click on Github login button
    await signUpPage.clickGithubLogin();

    // Verify redirect to Github OAuth
    await signUpPage.verifyRedirectToGithubOAuth();

    // Verify Github OAuth page loaded correctly
    await signUpPage.verifyGithubOAuthFlow();


    // Verify GitHub displays correct application information
    await signUpPage.verifyGithubApplicationInfo();

    // Complete Github OAuth login
    await signUpPage.completeGithubOAuth(githubUsername, githubPassword);

    // Verify the user is redirected to the home page after successful authentication
    const signInPage = new SignInPage(page);
    await signInPage.verifySuccessfulLogin();
  });
});


