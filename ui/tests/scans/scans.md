### E2E Tests: Scans - On Demand

**Suite ID:** `SCANS-E2E`
**Feature:** On-demand Scans.

---

## Test Case: `SCANS-E2E-001` - Execute On-Demand Scan

**Priority:** `critical`

**Tags:**

- type → @e2e, @serial
- feature → @scans

**Description/Objective:** Validates the complete flow to execute an on-demand scan selecting a provider by UID and confirming success on the Scans page.

**Preconditions:**

- Admin user authentication required (admin.auth.setup setup)
- Environment variables configured for : E2E_AWS_PROVIDER_ACCOUNT_ID,E2E_AWS_PROVIDER_ACCESS_KEY and E2E_AWS_PROVIDER_SECRET_KEY
- Remove any existing AWS provider with the same Account ID before starting the test
- This test must be run serially and never in parallel with other tests, as it requires the Account ID Provider to be already registered.

### Flow Steps:

1. Navigate to Scans page
2. Open provider selector and choose the entry whose text contains E2E_AWS_PROVIDER_ACCOUNT_ID
3. Optionally fill scan label (alias)
4. Click "Start now" to launch the scan
5. Verify the success toast appears
6. Verify a row in the Scans table contains the provided scan label (or shows the new scan entry)

### Expected Result:

- Scan is launched successfully
- Success toast is displayed to the user
- Scans table displays the new scan entry (including the alias when provided)

### Key verification points:

- Scans page loads correctly
- Provider select is available and lists the configured provider UID
- "Start now" button is rendered and enabled when form is valid
- Success toast message: "The scan was launched successfully."
- Table contains a row with the scan label or new scan state (queued/available/executing)

### Notes:

- The table may take a short time to reflect the new scan; assertions look for a row containing the alias.
- Provider cleanup performed before each test to ensure clean state
- Tests should run serially to avoid state conflicts.


