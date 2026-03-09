import { test } from "@playwright/test";
import { InvitationsPage } from "./invitations-page";
import { makeSuffix } from "../helpers";
import { SignUpPage } from "../sign-up/sign-up-page";
import { SignInPage } from "../sign-in-base/sign-in-base-page";
import { UserProfilePage } from "../profile/profile-page";

const isCloudEnv = process.env.NEXT_PUBLIC_IS_CLOUD_ENV === "true";

test.describe("New user invitation", () => {
  let invitationsPage: InvitationsPage;

  test.beforeEach(async ({ page }) => {
    invitationsPage = new InvitationsPage(page);
  });

  test.use({ storageState: "playwright/.auth/admin_user.json" });

  test(
    "should send an invitation successfully",
    {
      tag: ["@critical", "@e2e", "@invitations", "@INVITATION-E2E-001"],
    },
    async () => {
      const suffix = makeSuffix(10);
      const uniqueEmail = `e2e+${suffix}@prowler.com`;

      await invitationsPage.goto();
      await invitationsPage.verifyPageLoaded();

      await invitationsPage.clickInviteButton();
      await invitationsPage.verifyInvitePageLoaded();

      await invitationsPage.fillEmail(uniqueEmail);
      await invitationsPage.selectRole("admin");

      await invitationsPage.clickSendInviteButton();
      await invitationsPage.verifyInviteDataPageLoaded();
    },
  );

  test(
    "should invite a new user and verify signup and login",
    {
      tag: ["@critical", "@e2e", "@invitations", "@INVITATION-E2E-002"],
    },
    async ({ browser }) => {
      test.skip(!isCloudEnv, "Requires email-verification flow (Cloud only)");

      const password = process.env.E2E_NEW_USER_PASSWORD;
      const organizationId = process.env.E2E_ORGANIZATION_ID;

      if (!password || !organizationId) {
        throw new Error(
          "E2E_NEW_USER_PASSWORD or E2E_ORGANIZATION_ID environment variable is not set",
        );
      }

      const suffix = makeSuffix(10);
      const uniqueEmail = `e2e+${suffix}@prowler.com`;

      await invitationsPage.goto();
      await invitationsPage.verifyPageLoaded();

      await invitationsPage.clickInviteButton();
      await invitationsPage.verifyInvitePageLoaded();

      await invitationsPage.fillEmail(uniqueEmail);
      await invitationsPage.selectRole("admin");

      await invitationsPage.clickSendInviteButton();
      await invitationsPage.verifyInviteDataPageLoaded();

      const shareUrl = await invitationsPage.getShareUrl();

      const inviteContext = await browser.newContext({
        storageState: { cookies: [], origins: [] },
      });
      const signUpPage = new SignUpPage(await inviteContext.newPage());

      await signUpPage.gotoInvite(shareUrl);
      await signUpPage.signup({
        name: `E2E User ${suffix}`,
        email: uniqueEmail,
        password: password,
        confirmPassword: password,
        acceptTerms: true,
      });

      await signUpPage.verifyNoErrors();
      await signUpPage.verifyRedirectToLogin();

      const signInPage = new SignInPage(await inviteContext.newPage());
      await signInPage.goto();
      await signInPage.login({
        email: uniqueEmail,
        password: password,
      });
      await signInPage.verifySuccessfulLogin();

      const userProfilePage = new UserProfilePage(
        await inviteContext.newPage(),
      );
      await userProfilePage.goto();
      await userProfilePage.verifyOrganizationId(organizationId);

      await inviteContext.close();
    },
  );
});
