import { test, expect, request, Page } from '@playwright/test';

// Test credentials
const testEmail = 'test@gmail.com';
const testPassword = 'Testt@123456';

// Helper login function
const login = async (page: Page, email: string, password: string) => {
    await page.goto('/sign-in');
    await page.fill('input[name="email"]', email);
    await page.fill('input[name="password"]', password);
    await page.getByRole('button', { name: /log in/i }).click();
};

test.beforeAll(async () => {
    const apiContext = await request.newContext();
    const response = await apiContext.post(`${process.env.API_BASE_URL}/users`, {
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

    if (!response.ok()) {
        console.warn(`User creation may have failed: ${response.status()} - ${await response.text()}`);
    }

    await apiContext.dispose();
});

// Test invalid login
test('should show error for invalid credentials', async ({ page }) => {
    await login(page, 'wrong@gmail.com', 'WrongPassword123');
    await page.waitForTimeout(7000);
    await expect(page.getByText(/invalid email or password/i)).toBeVisible({ timeout: 10000 });
});

// Test valid login and redirection
test('should sign in successfully', async ({ page }) => {
    await login(page, testEmail, testPassword);
    await page.waitForTimeout(7000);
    await page.waitForURL((url) => !url.pathname.includes('sign-in'), {
        timeout: 15000,
    });
});

// Test session persistence after reload
test('should persist session after login', async ({ page }) => {
    await login(page, testEmail, testPassword);
    await page.waitForTimeout(7000);
    await page.waitForURL((url) => !url.pathname.includes('sign-in'), { timeout: 15000 });
    await page.reload();

    await expect(page.getByRole('button', { name: /sign out/i })).toBeVisible();

    await page.goto("/findings")
    await expect(page.getByText(/Browse all findings/i).first()).toBeVisible({ timeout: 10000 });
});
