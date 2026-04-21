import { expect, test } from "@playwright/test";

import { SignInPage } from "../sign-in-base/sign-in-base-page";
import { SignUpPage } from "../sign-up/sign-up-page";
import { InvitationAcceptPage } from "./invitation-accept-page";

test.describe("Invitation Accept Smart Router", () => {
  // Match the auth suites' timeout to handle slow dev server starts
  test.setTimeout(60000);

  test(
    "unauthenticated user sees choice screen and Sign in preserves token in callbackUrl",
    {
      tag: [
        "@e2e",
        "@invitation",
        "@invitation-accept",
        "@INVITE-ACCEPT-E2E-001",
      ],
    },
    async ({ page, context }) => {
      const invitationPage = new InvitationAcceptPage(page);
      const signInPage = new SignInPage(page);

      await context.clearCookies();

      const token = "test-token";
      await invitationPage.gotoWithToken(token);
      await invitationPage.verifyChoiceScreen();

      await invitationPage.signInButton.click();
      await signInPage.verifyRedirectWithCallback(
        `/invitation/accept?invitation_token=${token}`,
      );

      const callbackUrl = new URL(page.url()).searchParams.get("callbackUrl");
      expect(callbackUrl).toContain(`invitation_token=${token}`);
    },
  );

  test(
    '"Create an account" button redirects to sign-up with the invitation token',
    {
      tag: [
        "@e2e",
        "@invitation",
        "@invitation-accept",
        "@INVITE-ACCEPT-E2E-002",
      ],
    },
    async ({ page, context }) => {
      const invitationPage = new InvitationAcceptPage(page);
      const signUpPage = new SignUpPage(page);

      await context.clearCookies();

      const token = "test-token";
      await invitationPage.gotoWithToken(token);

      await expect(invitationPage.createAccountButton).toBeVisible();
      await invitationPage.createAccountButton.click();

      await page.waitForURL(/\/sign-up\?/);
      const url = new URL(page.url());
      expect(url.pathname).toBe("/sign-up");
      expect(url.searchParams.get("invitation_token")).toBe(token);

      await signUpPage.verifyPageLoaded();
    },
  );

  test(
    "navigating to /invitation/accept without a token shows the no-token error screen",
    {
      tag: [
        "@e2e",
        "@invitation",
        "@invitation-accept",
        "@INVITE-ACCEPT-E2E-004",
      ],
    },
    async ({ page, context }) => {
      const invitationPage = new InvitationAcceptPage(page);
      const signInPage = new SignInPage(page);

      await context.clearCookies();

      await invitationPage.gotoWithoutToken();
      await invitationPage.verifyNoTokenScreen();

      await invitationPage.goToSignInLink.click();
      await signInPage.verifyOnSignInPage();
    },
  );
});
