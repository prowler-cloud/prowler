import { test as authManageIntegrationsSetup } from '@playwright/test';
import { authenticateAndSaveState } from '@/tests/helpers';

const manageIntegrationsUserFile = 'playwright/.auth/manage_integrations_user.json';

authManageIntegrationsSetup('authenticate as integrations e2e user',  async ({ page }) => {
  const integrationsEmail = process.env.E2E_MANAGE_INTEGRATIONS_USER;
  const integrationsPassword = process.env.E2E_MANAGE_INTEGRATIONS_PASSWORD;
  
  if (!integrationsEmail || !integrationsPassword) {
    throw new Error('E2E_MANAGE_INTEGRATIONS_USER and E2E_MANAGE_INTEGRATIONS_PASSWORD environment variables are required');
  }

  await authenticateAndSaveState(page, integrationsEmail, integrationsPassword, manageIntegrationsUserFile);
});
