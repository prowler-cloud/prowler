### E2E Tests: Scans - On Demand

**Suite ID:** `SCAN-E2E`
**Feature:** On-demand Scans.

---

## Test Case: `SCAN-E2E-001` - Execute On-Demand Scan

**Priority:** `critical`

**Tags:**

- type → @e2e, @serial
- feature → @scans

**Description/Objective:** Validates the complete flow to execute an on-demand scan by opening the launch scan modal, selecting a provider by UID, adding an optional scan note, and confirming success on the Scans page.

**Preconditions:**

- Admin user authentication required (admin.auth.setup setup)
- Environment variables configured for : E2E_AWS_PROVIDER_ACCOUNT_ID,E2E_AWS_PROVIDER_ACCESS_KEY and E2E_AWS_PROVIDER_SECRET_KEY
- Remove any existing AWS provider with the same Account ID before starting the test
- This test must be run serially and never in parallel with other tests, as it requires the Account ID Provider to be already registered.

### Flow Steps:

1. Navigate to Scans page
2. Click "Launch Scan" to open the launch scan modal
3. Open the Cloud Account selector and choose the entry whose text contains E2E_AWS_PROVIDER_ACCOUNT_ID
4. Optionally fill Scan Note
5. Click "Launch Scan" in the modal
6. Verify the success toast appears
7. Verify a row in the Scans table contains the provider account ID

### Expected Result:

- Scan is launched successfully
- Success toast is displayed to the user
- Scans table displays a scan entry for the selected account

### Key verification points:

- Scans page loads correctly
- Launch Scan modal opens correctly
- Cloud Account select is available and lists the configured provider UID
- "Launch Scan" button is rendered and enabled when form is valid
- Success toast message: "The scan was launched successfully."
- Table contains a row with the selected account ID or new scan state (queued/available/executing)

### Notes:

- The table may take a short time to reflect the new scan; assertions look for a row containing the account ID.
- Provider cleanup performed before each test to ensure clean state
- Tests should run serially to avoid state conflicts.
