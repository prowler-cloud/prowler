import { test, expect } from '@playwright/test';

// Test credentials from environment variables
const TEST_USER_EMAIL = process.env.TEST_USER_EMAIL || 'dev@prowler.com';
const TEST_USER_PASSWORD = process.env.TEST_USER_PASSWORD || 'thisisapassword123';
const TEST_USER_NAME = process.env.TEST_USER_NAME || 'Prowler User';
const TEST_USER_COMPANY = process.env.TEST_USER_COMPANY || 'Prowler';

test.describe('Sign In', () => {
  test.beforeEach(async ({ page }) => {
    // Clear any existing authentication state
    await page.context().clearCookies();
  });

  test('should successfully login with valid credentials and sign out', async ({ page }) => {
    await page.goto('/sign-in');

    // Fill in the login form
    await page.getByLabel('Email').fill(TEST_USER_EMAIL);
    await page.getByLabel('Password').fill(TEST_USER_PASSWORD);

    // Submit the form
    await page.getByRole('button', { name: /log in/i }).click();

    await expect(page).toHaveURL('/');

    // Click user menu and then logout
    await page.getByRole('button', { name: /sign out/i }).click();
  });

  test('should show error with invalid credentials', async ({ page }) => {
    await page.goto('/sign-in');

    // Fill in the login form with invalid credentials
    await page.getByLabel('Email').fill(TEST_USER_EMAIL);
    await page.getByLabel('Password').fill('wrongpassword');

    // Submit the form
    await page.getByRole('button', { name: /log in/i }).click();

    // Verify error message is shown
    await expect(page.getByText(/invalid email or password/i)).toBeVisible();

    // Assert border color
    const emailInput =  page.getByLabel('Email');
    const passwordInput = page.getByLabel('Password');
    const emailInputBorderColor = await emailInput.evaluate((el) => {
      return window.getComputedStyle(el).borderColor;
    });
    const passwordInputBorderColor = await passwordInput.evaluate((el) => {
        return window.getComputedStyle(el).borderColor;
      });
    expect(emailInputBorderColor).toBe('rgb(229, 231, 235)');
    expect(passwordInputBorderColor).toBe('rgb(229, 231, 235)');
  });

  test('should maintain session after page reload', async ({ page }) => {
    // First login
    await page.goto('/sign-in');
    await page.getByLabel('Email').fill(TEST_USER_EMAIL);
    await page.getByLabel('Password').fill(TEST_USER_PASSWORD);
    await page.getByRole('button', { name: /log in/i }).click();

    // Wait for successful login
    await expect(page).toHaveURL('/');

    // Reload the page
    await page.reload();

    // Verify still logged in
    await expect(page).toHaveURL('/');
  });
});

test.describe('Sign Up', () => {
    test.beforeEach(async ({ page }) => {
        // Clear any existing authentication state
        await page.context().clearCookies();
      });

    test('should successfully register a new user, then sign in and sign out', async ({ page }) => {
    await page.goto('/sign-up');

    // Fill in the login form
    await page.getByPlaceholder('Enter your name').fill(TEST_USER_NAME);
    await page.getByPlaceholder('Enter your company name').fill(TEST_USER_COMPANY);
    // Generate a unique email for each run
    const randomEmail = `e2e+${Date.now()}@prowler.com`;
    await page.getByLabel('Email').fill(randomEmail);
    await page.getByLabel('Password', { exact: true }).fill(TEST_USER_PASSWORD);
    await page.getByLabel('Confirm Password', { exact: true }).fill(TEST_USER_PASSWORD);

    // Submit the form
    await page.getByRole('button', { name: /sign up/i }).click();

    // Assert the success message
    await expect(page.getByText('Success!', { exact: true })).toBeVisible();
    await expect(page.getByText('The user was registered successfully.', { exact: true })).toBeVisible();

    // Optionally, continue to assert the redirect
    await expect(page).toHaveURL('/sign-in');

    // Fill in the login form
    await page.getByLabel('Email').fill(randomEmail);
    await page.getByLabel('Password').fill(TEST_USER_PASSWORD);

    // Submit the form
    await page.getByRole('button', { name: /log in/i }).click();

    await expect(page).toHaveURL('/');

    // Click user menu and then logout
    await page.getByRole('button', { name: /sign out/i }).click();
    });

  });
