import { test as authManageScansSetup } from '@playwright/test';
import { SignInPage } from '../sign-in-base/sign-in-base-page';

const manageScansUserFile = 'playwright/.auth/manage_scans_user.json';

authManageScansSetup('authenticate as scans e2e user', async ({ page }) => {
  const scansEmail = process.env.E2E_MANAGE_SCANS_USER;
  const scansPassword = process.env.E2E_MANAGE_SCANS_PASSWORD;
  
  if (!scansEmail || !scansPassword) {
    throw new Error('E2E_MANAGE_SCANS_USER and E2E_MANAGE_SCANS_PASSWORD environment variables are required');
  }

  const signInPage = new SignInPage(page);
  await signInPage.authenticateAndSaveState({ email: scansEmail, password: scansPassword }, manageScansUserFile);
});
