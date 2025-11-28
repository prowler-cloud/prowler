### E2E Tests: User Sign-Up

**Suite ID:** `SIGNUP-E2E`
**Feature:** New user registration.

---

## Test Case: `SIGNUP-E2E-001` - Successful new user registration and login

**Priority:** `critical`

**Tags:**
- type → @e2e
- feature → @signup

**Description/Objetive:** Registers a new user with valid data, verifies redirect to Login (OSS), and confirms the user can authenticate.

**Preconditions:**
- Application is running, email domain & password is acceptable for sign-up.
- No existing data in Prowler is required; the test can run on a clean state.
- `E2E_NEW_USER_PASSWORD` environment variable must be set with a valid password for the test.

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
- The test requires the `E2E_NEW_USER_PASSWORD` environment variable to be set before running.


