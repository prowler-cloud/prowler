import { test as authUnlimitedVisibilitySetup } from '@playwright/test';
import { authenticateAndSaveState } from '@/tests/helpers';

const unlimitedVisibilityUserFile = 'playwright/.auth/unlimited_visibility_user.json';

authUnlimitedVisibilitySetup('authenticate as unlimited visibility e2e user',  async ({ page }) => {
  const unlimitedVisibilityEmail = process.env.E2E_UNLIMITED_VISIBILITY_USER;
  const unlimitedVisibilityPassword = process.env.E2E_UNLIMITED_VISIBILITY_PASSWORD;

  if (!unlimitedVisibilityEmail || !unlimitedVisibilityPassword) {
    throw new Error('E2E_UNLIMITED_VISIBILITY_USER and E2E_UNLIMITED_VISIBILITY_PASSWORD environment variables are required');
  }

  await authenticateAndSaveState(page, unlimitedVisibilityEmail, unlimitedVisibilityPassword, unlimitedVisibilityUserFile);
});
