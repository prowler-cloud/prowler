### E2E Tests: Invitations Management

**Suite ID:** `INVITATION-E2E`
**Feature:** User Invitations.

---

## Test Case: `INVITATION-E2E-001` - Invite New User and Complete Sign-Up

**Priority:** `critical`

**Tags:**

- type → @e2e
- feature → @invitations
- id → @INVITATION-E2E-001

**Description/Objective:** Validates the full flow to invite a new user from the admin session, consume the invitation link, sign up as the invited user, authenticate, and verify the user is associated to the expected organization.

**Preconditions:**

- Admin authentication state available: `playwright/.auth/admin_user.json` (admin.auth.setup)
- Environment variables configured:
  - `E2E_NEW_USER_PASSWORD` (password for the invited user)
  - `E2E_ORGANIZATION_ID` (expected organization for membership verification)
- Application running with accessible UI/API endpoints

### Flow Steps:

1. Navigate to invitations page
2. Click "Send Invitation" button
3. Fill unique email address for the invite
4. Select role `e2e_admin`
5. Click "Send Invitation" to generate invitation
6. Read the generated share URL from the invitation details
7. Open a new browser context (no admin cookies) and navigate to the share URL
8. Complete sign-up with provided password and accept terms
9. Verify sign-up success (no errors) and redirect to login page
10. Log in with the newly created credentials in the new context
11. Verify successful login
12. Navigate to user profile and verify `organizationId` matches `E2E_ORGANIZATION_ID`

### Expected Result:

- Invitation is created and a valid share URL is provided
- Invited user can sign up successfully using the invitation link
- User is redirected to the login page after sign-up (OSS flow)
- Login succeeds with the new credentials
- User profile shows membership in the expected organization

### Key verification points:

- Invitations page loads and displays the heading
- Send Invitation form is visible (email + role select)
- Invitation details page shows share URL
- Sign-up page loads from invitation link and submits without errors
- Post sign-up, redirect to login is performed
- Login with the new account succeeds
- Profile page shows the expected organization id

### Notes:

- Test uses a fresh browser context for the invitee to avoid admin session leakage
- Email should be unique per run (the test uses a random suffix)
- Ensure `E2E_NEW_USER_PASSWORD` and `E2E_ORGANIZATION_ID` are set before execution
- The role `e2e_admin` must be available in the environment