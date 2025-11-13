import { test as authManageScansSetup } from '@playwright/test';
import { authenticateAndSaveState } from '@/tests/helpers';

const manageScansUserFile = 'playwright/.auth/manage_scans_user.json';

authManageScansSetup('authenticate as scans e2e user', async ({ page }) => {
  const scansEmail = process.env.E2E_MANAGE_SCANS_USER;
  const scansPassword = process.env.E2E_MANAGE_SCANS_PASSWORD;
  
  if (!scansEmail || !scansPassword) {
    throw new Error('E2E_MANAGE_SCANS_USER and E2E_MANAGE_SCANS_PASSWORD environment variables are required');
  }

  await authenticateAndSaveState(page, scansEmail, scansPassword, manageScansUserFile);
});
