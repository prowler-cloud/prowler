import { test as authManageCloudProvidersSetup } from '@playwright/test';
import { SignInPage } from '../sign-in-base/sign-in-base-page';

const manageCloudProvidersUserFile = 'playwright/.auth/manage_cloud_providers_user.json';

authManageCloudProvidersSetup('authenticate as manage cloud providers e2e user',  async ({ page }) => {
  const cloudProvidersEmail = process.env.E2E_MANAGE_CLOUD_PROVIDERS_USER;
  const cloudProvidersPassword = process.env.E2E_MANAGE_CLOUD_PROVIDERS_PASSWORD;
    
  if (!cloudProvidersEmail || !cloudProvidersPassword) {
    throw new Error('E2E_MANAGE_CLOUD_PROVIDERS_USER and E2E_MANAGE_CLOUD_PROVIDERS_PASSWORD environment variables are required');
  }

  const signInPage = new SignInPage(page);
  await signInPage.authenticateAndSaveState({ email: cloudProvidersEmail, password: cloudProvidersPassword }, manageCloudProvidersUserFile);
});
