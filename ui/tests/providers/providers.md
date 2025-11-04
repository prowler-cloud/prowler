### E2E Tests: AWS Provider Management

**Suite ID:** `PROVIDER-E2E`
**Feature:** AWS Provider Management - Add and configure AWS cloud providers with different authentication methods

---

## Test Case: `PROVIDER-E2E-001` - Add AWS Provider with Static Credentials

**Priority:** `critical`

**Tags:**

- type → @e2e, @serial
- feature → @providers
- provider → @aws

**Description/Objective:** Validates the complete flow of adding a new AWS provider using static access key credentials

**Preconditions:**

- Admin user authentication required (admin.auth.setup setup)
- Environment variables configured: E2E_AWS_PROVIDER_ACCOUNT_ID, E2E_AWS_PROVIDER_ACCESS_KEY and E2E_AWS_PROVIDER_SECRET_KEY
- Remove any existing provider with the same Account ID before starting the test
- This test must be run serially and never in parallel with other tests, as it requires the Account ID not to be already registered beforehand.

### Flow Steps:

1. Navigate to providers page
2. Click "Add Provider" button
3. Select AWS provider type
4. Fill provider details (account ID and alias)
5. Select "credentials" authentication type
6. Fill static credentials (access key and secret key)
7. Launch initial scan
8. Verify redirect to provider management page

### Expected Result:

- AWS provider successfully added with static credentials
- Initial scan launched successfully
- User redirected to provider details page

### Key verification points:

- Provider page loads correctly
- Connect account page displays AWS option
- Credentials form accepts static credentials
- Launch scan page appears
- Successful redirect to provider page after scan launch

### Notes:

- Test uses environment variables for AWS credentials
- Provider cleanup performed before each test to ensure clean state
- Requires valid AWS account with appropriate permissions

---

## Test Case: `PROVIDER-E2E-002` - Add AWS Provider with Assume Role Credentials Access Key and Secret Key

**Priority:** `critical`

**Tags:**

- type → @e2e, @serial
- feature → @providers
- provider → @aws

**Description/Objective:** Validates the complete flow of adding a new AWS provider using role-based authentication with Access Key and Secret Key

**Preconditions:**

- Admin user authentication required (admin.auth.setup setup)
- Environment variables configured: E2E_AWS_PROVIDER_ACCOUNT_ID, E2E_AWS_PROVIDER_ACCESS_KEY, E2E_AWS_PROVIDER_SECRET_KEY, E2E_AWS_PROVIDER_ROLE_ARN
- Remove any existing provider with the same Account ID before starting the test
- This test must be run serially and never in parallel with other tests, as it requires the Account ID not to be already registered beforehand.

### Flow Steps:

1. Navigate to providers page
2. Click "Add Provider" button
3. Select AWS provider type
4. Fill provider details (account ID and alias)
5. Select "role" authentication type
6. Fill role credentials (access key, secret key, and role ARN)
7. Launch initial scan
8. Verify redirect to provider management page

### Expected Result:

- AWS provider successfully added with role credentials
- Initial scan launched successfully
- User redirected to provider details page

### Key verification points:

- Provider page loads correctly
- Connect account page displays AWS option
- Role credentials form accepts all required fields
- Launch scan page appears
- Successful redirect to provider page after scan launch

### Notes:

- Test uses environment variables for AWS credentials and role ARN
- Provider cleanup performed before each test to ensure clean state
- Requires valid AWS account with role assumption permissions
- Role ARN must be properly configured

---

## Test Case: `PROVIDER-E2E-003` - Add Azure Provider with Static Credentials

**Priority:** `critical`

**Tags:**

- type → @e2e, @serial
- feature → @providers
- provider → @azure

**Description/Objective:** Validates the complete flow of adding a new Azure provider using static client credentials (Client ID, Client Secret, Tenant ID)

**Preconditions:**

- Admin user authentication required (admin.auth.setup setup)
- Environment variables configured: E2E_AZURE_SUBSCRIPTION_ID, E2E_AZURE_CLIENT_ID, E2E_AZURE_SECRET_ID, E2E_AZURE_TENANT_ID
- Remove any existing provider with the same Subscription ID before starting the test
- This test must be run serially and never in parallel with other tests, as it requires the Subscription ID not to be already registered beforehand.

### Flow Steps:

1. Navigate to providers page
2. Click "Add Provider" button
3. Select Azure provider type
4. Fill provider details (subscription ID and alias)
5. Fill Azure credentials (client ID, client secret, tenant ID)
6. Launch initial scan
7. Verify redirect to provider management page

### Expected Result:

- Azure provider successfully added with static credentials
- Initial scan launched successfully
- User redirected to provider details page

### Key verification points:

- Provider page loads correctly
- Connect account page displays Azure option
- Azure credentials form accepts all required fields
- Launch scan page appears
- Successful redirect to provider page after scan launch

### Notes:

- Test uses environment variables for Azure credentials
- Provider cleanup performed before each test to ensure clean state
- Requires valid Azure subscription with appropriate permissions
- Client credentials must have sufficient permissions for security scanning
