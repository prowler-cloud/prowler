import { test, expect } from '@playwright/test';

test('Unauthenticated users are redirected to sign-in and can navigate to sign-up', async ({ page }) => {
    await page.goto('/');
    await expect(page).toHaveURL(/\/sign-in/);
    await expect(page.getByText('Sign In')).toBeVisible();

    await page.getByRole('link', { name: /sign up/i }).click();
    await expect(page).toHaveURL(/\/sign-up/);
});