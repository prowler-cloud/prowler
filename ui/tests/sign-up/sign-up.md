# E2E Tests: User Sign-Up

**Suite ID:** `SIGNUP-E2E`
**Feature:** New user registration flow.

---

## Test Case: `SIGNUP-E2E-001` - Successful new user registration and login

**Priority:** `critical`

**Tags:**
- type → @e2e
- feature → @signup

**Description/Objetive:** Registers a new user with valid data, verifies redirect to Login, and confirms the user can authenticate.

**Preconditions:**
- Application is running, email domain & password is acceptable for sign-up.
- No existing data in Prowler is required; the test can run on a clean state.

### Flow Steps:
1. Navigate to the Sign up page.
2. Fill the form with valid data (unique email, valid password, terms accepted).
3. Submit the form.
4. Verify redirect to the Login page.
5. Log in with the newly created credentials.

### Expected Result:
- Sign-up succeeds and redirects to Login.
- User can log in successfully using the created credentials and reach the home page.

### Key verification points:
- After submitting sign-up, the URL changes to `/sign-in`.
- The newly created credentials can be used to sign in successfully.
- After login, the user lands on the home (`/`) and main content is visible.

### Notes:
- Test data uses a random base36 suffix to avoid collisions with email.

---

## Test Case: `SIGNUP-E2E-002` - Github Social Sign-up OAuth Flow

**Priority:** `critical`

**Tags:**
- type → @e2e
- feature → @signup
- social → @social

**Description/Objective:** Validates that users can complete the full Github OAuth flow for social sign-up, including authentication and successful return to Prowler

**Preconditions:**
- Application is running 
- Github OAuth app is configured
- E2E_GITHUB_USER and E2E_GITHUB_PASSWORD environment variables are set with valid Github credentials

### Flow Steps:
1. Navigate to sign-up page
2. Verify page loads with social login options
3. Verify Github login button is visible and enabled
4. Click "Continue with Github" button
5. Verify redirect to Github OAuth page
6. Verify OAuth configuration parameters
7. Fill Github credentials (username and password)
8. Submit Github login form
9. Verify successful redirect back to Prowler

### Expected Result:
- User is redirected to Github OAuth authorization page
- OAuth URL contains correct client_id, redirect_uri, and scope parameters
- Github OAuth page displays proper application information
- User can successfully authenticate with Github credentials
- User is redirected back to Prowler application after successful authentication


### Key verification points:
- Github button is visible and clickable on sign-up page
- Redirect to github.com/login occurs correctly
- OAuth URL structure follows GitHub OAuth format (https://github.com/login)
- GitHub OAuth page displays Prowler application logo and information
- GitHub OAuth page shows correct consent message "to continue to Prowler"
- GitHub OAuth page shows "Sign in to GitHub" header
- GitHub login form elements are present and accessible (username/email, password, sign in button)
- Github login form accepts credentials correctly
- Successful authentication redirects back to Prowler home
- After redirect, verify authenticated area is visible (e.g., main dashboard content)

### Notes:
- Test requires E2E_GITHUB_USER and E2E_GITHUB_PASSWORD environment variables
- Test completes full OAuth flow including Github authentication
- Test verifies successful social sign-up integration
- Github credentials must be valid for test to pass


