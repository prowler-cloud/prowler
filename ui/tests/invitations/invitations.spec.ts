import { test } from "@playwright/test";
import { InvitationsPage } from "./invitations-page";
import { makeSuffix } from "../helpers";
import { SignUpPage } from "../sign-up/sign-up-page";
import { SignInPage } from "../sign-in-base/sign-in-base-page";
import { UserProfilePage } from "../profile/profile-page";

test.describe("New user invitation", () => {
  // Invitations page object
  let invitationsPage: InvitationsPage;

  // Setup before each test
  test.beforeEach(async ({ page }) => {
    invitationsPage = new InvitationsPage(page);
  });

  // Use admin authentication for invitations management
  test.use({ storageState: "playwright/.auth/admin_user.json" });

  test(
    "should invite a new user",
    {
      tag: ["@critical", "@e2e", "@invitations", "@INVITATION-E2E-001"],
    },
    async ({ page, browser }) => {

      // Test data from environment variables
      const password = process.env.E2E_NEW_USER_PASSWORD;
      const organizationId = process.env.E2E_ORGANIZATION_ID;

      // Validate required environment variables
      if (!password || !organizationId) {
        throw new Error(
          "E2E_NEW_USER_PASSWORD or E2E_ORGANIZATION_ID environment variable is not set",
        );
      }

      // Generate unique test data
      const suffix = makeSuffix(10);
      const uniqueEmail = `e2e+${suffix}@prowler.com`;

      // Navigate to providers page
      await invitationsPage.goto();
      await invitationsPage.verifyPageLoaded();

      // Press the invite button
      await invitationsPage.clickInviteButton();
      await invitationsPage.verifyInvitePageLoaded();

      // Fill the email
      await invitationsPage.fillEmail(uniqueEmail);

      // Select the role option
      await invitationsPage.selectRole("e2e_admin");

      // Press the send invitation button
      await invitationsPage.clickSendInviteButton();
      await invitationsPage.verifyInviteDataPageLoaded();

      // Get the share url
      const shareUrl = await invitationsPage.getShareUrl();

      // Navigate to the share url with a new context to avoid cookies from the admin context
      const inviteContext = await browser.newContext({ storageState: { cookies: [], origins: [] } });
      const signUpPage = new SignUpPage(await inviteContext.newPage());

      // Navigate to the share url
      await signUpPage.gotoInvite(shareUrl);

      // Fill and submit the sign-up form
      await signUpPage.signup({
        name: `E2E User ${suffix}`,
        email: uniqueEmail,
        password: password,
        confirmPassword: password,
        acceptTerms: true,
      });

      // Verify no errors occurred during sign-up
      await signUpPage.verifyNoErrors();

      // Verify redirect to login page (OSS environment)
      await signUpPage.verifyRedirectToLogin();

      // Verify the newly created user can log in successfully with the new context
      const signInPage = new SignInPage(await inviteContext.newPage());
      await signInPage.goto();
      await signInPage.login({
        email: uniqueEmail,
        password: password,
      });
      await signInPage.verifySuccessfulLogin();
      
      // Navigate to the user profile page
      const userProfilePage = new UserProfilePage(await inviteContext.newPage());
      await userProfilePage.goto();

      // Verify if user is added to the organization
      await userProfilePage.verifyOrganizationId(organizationId);

      // Close the invite context
      await inviteContext.close();
    },
  );
});
