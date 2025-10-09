import { test as authManageAccountSetup } from '@playwright/test';
import { authenticateAndSaveState } from '@/tests/helpers';

const manageAccountUserFile = 'playwright/.auth/manage_account_user.json';

authManageAccountSetup('authenticate as manage account e2e user',  async ({ page }) => {
  const accountEmail = process.env.E2E_MANAGE_ACCOUNT_USER;
  const accountPassword = process.env.E2E_MANAGE_ACCOUNT_PASSWORD;
  
  
  if (!accountEmail || !accountPassword) {
    throw new Error('E2E_MANAGE_ACCOUNT_USER and E2E_MANAGE_ACCOUNT_PASSWORD environment variables are required');
  }

  await authenticateAndSaveState(page, accountEmail, accountPassword, manageAccountUserFile);
});
