import { test as authInviteAndManageUsersSetup } from '@playwright/test';
import { SignInPage } from '../sign-in-base/sign-in-base-page';

const inviteAndManageUsersUserFile = 'playwright/.auth/invite_and_manage_users_user.json';

authInviteAndManageUsersSetup('authenticate as invite and manage users e2e user', async ({ page }) => {
  const inviteAndManageUsersEmail = process.env.E2E_INVITE_AND_MANAGE_USERS_USER;
  const inviteAndManageUsersPassword = process.env.E2E_INVITE_AND_MANAGE_USERS_PASSWORD;
  
  if (!inviteAndManageUsersEmail || !inviteAndManageUsersPassword) {
    throw new Error('E2E_INVITE_AND_MANAGE_USERS_USER and E2E_INVITE_AND_MANAGE_USERS_PASSWORD environment variables are required');
  }

  const signInPage = new SignInPage(page);
  await signInPage.authenticateAndSaveState({ email: inviteAndManageUsersEmail, password: inviteAndManageUsersPassword }, inviteAndManageUsersUserFile);
});
