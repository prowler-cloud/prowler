import { test as authManageAccountSetup } from '@playwright/test';
import { SignInPage } from '../sign-in-base/sign-in-base-page';

const manageAccountUserFile = 'playwright/.auth/manage_account_user.json';

authManageAccountSetup('authenticate as manage account e2e user',  async ({ page }) => {
  const accountEmail = process.env.E2E_MANAGE_ACCOUNT_USER;
  const accountPassword = process.env.E2E_MANAGE_ACCOUNT_PASSWORD;
  
  if (!accountEmail || !accountPassword) {
    throw new Error('E2E_MANAGE_ACCOUNT_USER and E2E_MANAGE_ACCOUNT_PASSWORD environment variables are required');
  }

  const signInPage = new SignInPage(page);
  await signInPage.authenticateAndSaveState({ email: accountEmail, password: accountPassword }, manageAccountUserFile);
});
