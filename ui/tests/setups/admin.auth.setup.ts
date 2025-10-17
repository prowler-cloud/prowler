import { test as authAdminSetup } from '@playwright/test';
import { authenticateAndSaveState } from '@/tests/helpers';

const adminUserFile = 'playwright/.auth/admin_user.json';

authAdminSetup('authenticate as admin e2e user', async ({ page }) => {

  const adminEmail = process.env.E2E_ADMIN_USER;
  const adminPassword = process.env.E2E_ADMIN_PASSWORD;

  if (!adminEmail || !adminPassword) {
    throw new Error('E2E_ADMIN_USER and E2E_ADMIN_PASSWORD environment variables are required');
  }

  await authenticateAndSaveState(page, adminEmail, adminPassword, adminUserFile);
});