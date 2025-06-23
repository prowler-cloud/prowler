import { test, expect } from '@playwright/test';

// Test credentials from environment variables
const TEST_USER_EMAIL = process.env.TEST_USER_EMAIL || 'dev@prowler.com';
const TEST_USER_PASSWORD = process.env.TEST_USER_PASSWORD || 'thisisapassword123';

test('should render login page with expected elements', async ({ page }) => {
    await page.goto('/login');
    await expect(page.locator('input[name="email"]')).toBeVisible();
    await expect(page.locator('input[name="password"]')).toBeVisible();
    await expect(page.getByRole('button', { name: 'Log In' })).toBeVisible();
});

test('should show error for invalid login', async ({ page }) => {
    await page.goto('/login');
    await page.fill('input[name="email"]', 'test@example.com');
    await page.fill('input[name="password"]', 'password');
    await page.click('button[type="submit"]');

    await expect(page.getByText(/invalid email or password/i)).toBeVisible();
});

test('should login and show "No results" message on Findings page search', async ({ page }) => {
    await page.goto('/login');
    const title = await page.title();

    await page.fill('input[name="email"]', TEST_USER_EMAIL);
    await page.fill('input[name="password"]', TEST_USER_PASSWORD);
    await page.click('button[type="submit"]');
    await page.waitForURL('/');
    await page.goto('/findings');
    await page.waitForSelector('input[type="text"]');
    await page.fill('input[type="text"]', 'findingsTest');
    await page.waitForSelector('table');
    await expect(page.getByText('No results.')).toBeVisible();
});