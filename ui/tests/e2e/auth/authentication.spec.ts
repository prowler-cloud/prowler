import { test, expect, request } from '@playwright/test';

// Test credentials
const testEmail = 'test@gmail.com';
const testPassword = 'Testt@123456';

test.beforeAll(async () => {
    const apiContext = await request.newContext();

    await apiContext.post(`${process.env.API_BASE_URL}users`, {
        headers: {
            'Content-Type': 'application/vnd.api+json',
            'Accept': 'application/vnd.api+json',
        },
        data: {
            data: {
                type: 'users',
                attributes: {
                    name: 'testuser',
                    email: testEmail,
                    password: testPassword,
                    company_name: 'test',
                },
            },
        },
    });

    await apiContext.dispose();
});

test('should show error for invalid credentials', async ({ page }) => {
    await page.goto('/sign-in');

    await page.fill('input[name="email"]', 'wrong@gmail.com');
    await page.fill('input[name="password"]', 'WrongPassword123');
    await page.getByRole('button', { name: /log in/i }).click();
    await page.waitForTimeout(7000);
    await expect(page.getByText(/invalid email or password/i)).toBeVisible({ timeout: 10000 });

});

test('should sign in successfully', async ({ page }) => {
    // Go to login page
    await page.goto('/sign-in');

    // Fill login form
    await page.fill('input[name="email"]', testEmail);
    await page.fill('input[name="password"]', testPassword);

    // Submit the form
    await page.getByRole('button', { name: /log in/i }).click();
    await page.waitForTimeout(7000);
    await page.waitForURL((url) => !url.pathname.includes('sign-in'), {
        timeout: 15000,
    });
});
