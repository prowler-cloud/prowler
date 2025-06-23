import { test } from '@playwright/test';

// Test credentials from environment variables
const TEST_USER_EMAIL = process.env.TEST_USER_EMAIL || 'dev@prowler.com';
const TEST_USER_PASSWORD = process.env.TEST_USER_PASSWORD || 'thisisapassword123';

test('should login successfully and redirect to home page', async ({ page }) => {
    await page.goto('/login');
    const title = await page.title();

    await page.fill('input[name="email"]', TEST_USER_EMAIL);
    await page.fill('input[name="password"]', TEST_USER_PASSWORD);
    await page.click('button[type="submit"]');
    await page.waitForURL('/');
});