### E2E Tests: AWS Provider Management

**Suite ID:** `PROVIDER-E2E`
**Feature:** AWS Provider Management.

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
8. Verify redirect to Scans page
9. Verify scheduled scan status in Scans table (provider exists and scan name is "scheduled scan")

### Expected Result:

- AWS provider successfully added with static credentials
- Initial scan launched successfully
- User redirected to Scans page
- Scheduled scan appears in Scans table with correct provider and scan name

### Key verification points:

- Provider page loads correctly
- Connect account page displays AWS option
- Credentials form accepts static credentials
- Launch scan page appears
- Successful redirect to Scans page after scan launch
- Provider exists in Scans table (verified by account ID)
- Scan name field contains "scheduled scan"

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
8. Verify redirect to Scans page
9. Verify scheduled scan status in Scans table (provider exists and scan name is "scheduled scan")

### Expected Result:

- AWS provider successfully added with role credentials
- Initial scan launched successfully
- User redirected to Scans page
- Scheduled scan appears in Scans table with correct provider and scan name

### Key verification points:

- Provider page loads correctly
- Connect account page displays AWS option
- Role credentials form accepts all required fields
- Launch scan page appears
- Successful redirect to Scans page after scan launch
- Provider exists in Scans table (verified by account ID)
- Scan name field contains "scheduled scan"

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
7. Verify redirect to Scans page
8. Verify scheduled scan status in Scans table (provider exists and scan name is "scheduled scan")

### Expected Result:

- Azure provider successfully added with static credentials
- Initial scan launched successfully
- User redirected to Scans page
- Scheduled scan appears in Scans table with correct provider and scan name

### Key verification points:

- Provider page loads correctly
- Connect account page displays Azure option
- Azure credentials form accepts all required fields
- Launch scan page appears
- Successful redirect to Scans page after scan launch
- Provider exists in Scans table (verified by subscription ID)
- Scan name field contains "scheduled scan"

### Notes:

- Test uses environment variables for Azure credentials
- Provider cleanup performed before each test to ensure clean state
- Requires valid Azure subscription with appropriate permissions
- Client credentials must have sufficient permissions for security scanning

---

## Test Case: `PROVIDER-E2E-004` - Add M365 Provider with Static Credentials

**Priority:** `critical`

**Tags:**

- type → @e2e, @serial
- feature → @providers
- provider → @m365

**Description/Objective:** Validates the complete flow of adding a new Microsoft 365 provider using static client credentials (Client ID, Client Secret, Tenant ID) tied to a Domain ID.

**Preconditions:**

- Admin user authentication required (admin.auth.setup setup)
- Environment variables configured: E2E_M365_DOMAIN_ID, E2E_M365_CLIENT_ID, E2E_M365_SECRET_ID, E2E_M365_TENANT_ID
- Remove any existing provider with the same Domain ID before starting the test
- This test must be run serially and never in parallel with other tests, as it requires the Domain ID not to be already registered beforehand.

### Flow Steps:

1. Navigate to providers page
2. Click "Add Provider" button
3. Select M365 provider type
4. Fill provider details (domain ID and alias)
5. Select static credentials type
6. Fill M365 credentials (client ID, client secret, tenant ID)
7. Launch initial scan
8. Verify redirect to Scans page
9. Verify scheduled scan status in Scans table (provider exists and scan name is "scheduled scan")

### Expected Result:

- M365 provider successfully added with static credentials
- Initial scan launched successfully
- User redirected to Scans page
- Scheduled scan appears in Scans table with correct provider and scan name

### Key verification points:

- Provider page loads correctly
- Connect account page displays M365 option
- M365 credentials form accepts all required fields
- Launch scan page appears
- Successful redirect to Scans page after scan launch
- Provider exists in Scans table (verified by domain ID)
- Scan name field contains "scheduled scan"

### Notes:

- Test uses environment variables for M365 credentials
- Provider cleanup performed before each test to ensure clean state
- Requires valid Microsoft 365 tenant with appropriate permissions
- Client credentials must have sufficient permissions for security scanning

---

## Test Case: `PROVIDER-E2E-005` - Add M365 Provider with Certificate Credentials

**Priority:** `critical`

**Tags:**

- type → @e2e, @serial
- feature → @providers
- provider → @m365

**Description/Objective:** Validates the complete flow of adding a new Microsoft 365 provider using certificate-based authentication (Client ID, Tenant ID, Certificate Content) tied to a Domain ID.

**Preconditions:**

- Admin user authentication required (admin.auth.setup setup)
- Environment variables configured: E2E_M365_DOMAIN_ID, E2E_M365_CLIENT_ID, E2E_M365_TENANT_ID, E2E_M365_CERTIFICATE_CONTENT
- Remove any existing provider with the same Domain ID before starting the test
- This test must be run serially and never in parallel with other tests, as it requires the Domain ID not to be already registered beforehand.

### Flow Steps:

1. Navigate to providers page
2. Click "Add Provider" button
3. Select M365 provider type
4. Fill provider details (domain ID and alias)
5. Select certificate credentials type
6. Fill M365 certificate credentials (client ID, tenant ID, certificate content)
7. Launch initial scan
8. Verify redirect to Scans page
9. Verify scheduled scan status in Scans table (provider exists and scan name is "scheduled scan")

### Expected Result:

- M365 provider successfully added with certificate credentials
- Initial scan launched successfully
- User redirected to Scans page
- Scheduled scan appears in Scans table with correct provider and scan name

### Key verification points:

- Provider page loads correctly
- Connect account page displays M365 option
- Certificate credentials form accepts all required fields
- Launch scan page appears
- Successful redirect to Scans page after scan launch
- Provider exists in Scans table (verified by domain ID)
- Scan name field contains "scheduled scan"

### Notes:

- Test uses environment variables for M365 certificate credentials
- Provider cleanup performed before each test to ensure clean state
- Requires valid Microsoft 365 tenant with certificate-based authentication
- Certificate must be properly configured and have sufficient permissions for security scanning

---

## Test Case: `PROVIDER-E2E-006` - Add Kubernetes Provider with Kubeconfig Content

**Priority:** `critical`

**Tags:**

- type → @e2e, @serial
- feature → @providers
- provider → @kubernetes

**Description/Objective:** Validates the complete flow of adding a new Kubernetes provider using kubeconfig content authentication

**Preconditions:**

- Admin user authentication required (admin.auth.setup setup)
- Environment variables configured: E2E_KUBERNETES_CONTEXT, E2E_KUBERNETES_KUBECONFIG_PATH
- Kubeconfig file must exist at the specified path
- Remove any existing provider with the same Context before starting the test
- This test must be run serially and never in parallel with other tests, as it requires the Context not to be already registered beforehand.

### Flow Steps:

1. Navigate to providers page
2. Click "Add Provider" button
3. Select Kubernetes provider type
4. Fill provider details (context and alias)
5. Verify credentials page is loaded
6. Fill Kubernetes credentials (kubeconfig content)
7. Launch initial scan
8. Verify redirect to Scans page
9. Verify scheduled scan status in Scans table (provider exists and scan name is "scheduled scan")

### Expected Result:

- Kubernetes provider successfully added with kubeconfig content
- Initial scan launched successfully
- User redirected to Scans page
- Scheduled scan appears in Scans table with correct provider and scan name

### Key verification points:

- Provider page loads correctly
- Connect account page displays Kubernetes option
- Provider details form accepts context and alias
- Credentials page loads with kubeconfig content field
- Kubeconfig content is properly filled in the correct field
- Launch scan page appears
- Successful redirect to Scans page after scan launch
- Provider exists in Scans table (verified by context)
- Scan name field contains "scheduled scan"

### Notes:

- Test uses environment variables for Kubernetes context and kubeconfig file path
- Kubeconfig content is read from file and used for authentication
- Provider cleanup performed before each test to ensure clean state
- Requires valid Kubernetes cluster with accessible kubeconfig
- Kubeconfig must have sufficient permissions for security scanning
- Test validates that kubeconfig content goes to the correct field (not the context field)

---

## Test Case: `PROVIDER-E2E-007` - Add GCP Provider with Service Account Key

**Priority:** `critical`

**Tags:**

- type → @e2e, @serial
- feature → @providers
- provider → @gcp

**Description/Objective:** Validates the complete flow of adding a new GCP provider using service account key authentication

**Preconditions:**

- Admin user authentication required (admin.auth.setup setup)
- Environment variables configured: E2E_GCP_PROJECT_ID, E2E_GCP_BASE64_SERVICE_ACCOUNT_KEY
- Remove any existing provider with the same Project ID before starting the test
- This test must be run serially and never in parallel with other tests, as it requires the Project ID not to be already registered beforehand.

### Flow Steps:

1. Navigate to providers page
2. Click "Add Provider" button
3. Select GCP provider type
4. Fill provider details (project ID and alias)
5. Select service account credentials type
6. Fill GCP service account key credentials
7. Launch initial scan
8. Verify redirect to Scans page
9. Verify scheduled scan status in Scans table (provider exists and scan name is "scheduled scan")

### Expected Result:

- GCP provider successfully added with service account key
- Initial scan launched successfully
- User redirected to Scans page
- Scheduled scan appears in Scans table with correct provider and scan name

### Key verification points:

- Provider page loads correctly
- Connect account page displays GCP option
- Provider details form accepts project ID and alias
- Service account credentials page loads with service account key field
- Service account key is properly filled in the correct field
- Launch scan page appears
- Successful redirect to Scans page after scan launch
- Provider exists in Scans table (verified by project ID)
- Scan name field contains "scheduled scan"

### Notes:

- Test uses environment variables for GCP project ID and service account key
- Service account key is provided as base64 encoded JSON content
- Provider cleanup performed before each test to ensure clean state
- Requires valid GCP project with service account having appropriate permissions
- Service account must have sufficient permissions for security scanning
- Test validates that service account key goes to the correct field
- Test uses base64 encoded environment variables for GCP service account key

---

## Test Case: `PROVIDER-E2E-008` - Add GitHub Provider with Personal Access Token

**Priority:** `critical`

**Tags:**

- type → @e2e, @serial
- feature → @providers
- provider → @github

**Description/Objective:** Validates the complete flow of adding a new GitHub provider using personal access token authentication for a user account

**Preconditions:**

- Admin user authentication required (admin.auth.setup setup)
- Environment variables configured: E2E_GITHUB_USERNAME, E2E_GITHUB_PERSONAL_ACCESS_TOKEN
- Remove any existing provider with the same Username before starting the test
- This test must be run serially and never in parallel with other tests, as it requires the Username not to be already registered beforehand.

### Flow Steps:

1. Navigate to providers page
2. Click "Add Provider" button
3. Select GitHub provider type
4. Fill provider details (username and alias)
5. Select personal access token credentials type
6. Fill GitHub personal access token credentials
7. Launch initial scan
8. Verify redirect to Scans page
9. Verify scheduled scan status in Scans table (provider exists and scan name is "scheduled scan")

### Expected Result:

- GitHub provider successfully added with personal access token
- Initial scan launched successfully
- User redirected to Scans page
- Scheduled scan appears in Scans table with correct provider and scan name

### Key verification points:

- Provider page loads correctly
- Connect account page displays GitHub option
- Provider details form accepts username and alias
- Personal access token credentials page loads with token field
- Personal access token is properly filled in the correct field
- Launch scan page appears
- Successful redirect to Scans page after scan launch
- Provider exists in Scans table (verified by username)
- Scan name field contains "scheduled scan"

### Notes:

- Test uses environment variables for GitHub username and personal access token
- Provider cleanup performed before each test to ensure clean state
- Requires valid GitHub account with personal access token
- Personal access token must have sufficient permissions for security scanning
- Test validates that personal access token goes to the correct field

---

## Test Case: `PROVIDER-E2E-009` - Add GitHub Provider with GitHub App

**Priority:** `critical`

**Tags:**

- type → @e2e, @serial
- feature → @providers
- provider → @github

**Description/Objective:** Validates the complete flow of adding a new GitHub provider using GitHub App authentication for a user account

**Preconditions:**

- Admin user authentication required (admin.auth.setup setup)
- Environment variables configured: E2E_GITHUB_USERNAME, E2E_GITHUB_APP_ID, E2E_GITHUB_BASE64_APP_PRIVATE_KEY
- Remove any existing provider with the same Username before starting the test
- This test must be run serially and never in parallel with other tests, as it requires the Username not to be already registered beforehand.

### Flow Steps:

1. Navigate to providers page
2. Click "Add Provider" button
3. Select GitHub provider type
4. Fill provider details (username and alias)
5. Select GitHub App credentials type
6. Fill GitHub App credentials (App ID and private key)
7. Launch initial scan
8. Verify redirect to Scans page
9. Verify scheduled scan status in Scans table (provider exists and scan name is "scheduled scan")

### Expected Result:

- GitHub provider successfully added with GitHub App credentials
- Initial scan launched successfully
- User redirected to Scans page
- Scheduled scan appears in Scans table with correct provider and scan name

### Key verification points:

- Provider page loads correctly
- Connect account page displays GitHub option
- Provider details form accepts username and alias
- GitHub App credentials page loads with App ID and private key fields
- GitHub App credentials are properly filled in the correct fields
- Launch scan page appears
- Successful redirect to Scans page after scan launch
- Provider exists in Scans table (verified by username)
- Scan name field contains "scheduled scan"

### Notes:

- Test uses environment variables for GitHub username, App ID, and base64 encoded private key
- Private key is base64 encoded and must be decoded before use
- Provider cleanup performed before each test to ensure clean state
- Requires valid GitHub App with App ID and private key
- GitHub App must have sufficient permissions for security scanning
- Test validates that GitHub App credentials go to the correct fields

---

## Test Case: `PROVIDER-E2E-010` - Add GitHub Provider with Organization Personal Access Token

**Priority:** `critical`

**Tags:**

- type → @e2e, @serial
- feature → @providers
- provider → @github

**Description/Objective:** Validates the complete flow of adding a new GitHub provider using organization personal access token authentication

**Preconditions:**

- Admin user authentication required (admin.auth.setup setup)
- Environment variables configured: E2E_GITHUB_ORGANIZATION, E2E_GITHUB_ORGANIZATION_ACCESS_TOKEN
- Remove any existing provider with the same Organization name before starting the test
- This test must be run serially and never in parallel with other tests, as it requires the Organization name not to be already registered beforehand.

### Flow Steps:

1. Navigate to providers page
2. Click "Add Provider" button
3. Select GitHub provider type
4. Fill provider details (organization name and alias)
5. Select personal access token credentials type
6. Fill GitHub organization personal access token credentials
7. Launch initial scan
8. Verify redirect to Scans page
9. Verify scheduled scan status in Scans table (provider exists and scan name is "scheduled scan")

### Expected Result:

- GitHub provider successfully added with organization personal access token
- Initial scan launched successfully
- User redirected to Scans page
- Scheduled scan appears in Scans table with correct provider and scan name

### Key verification points:

- Provider page loads correctly
- Connect account page displays GitHub option
- Provider details form accepts organization name and alias
- Personal access token credentials page loads with token field
- Organization personal access token is properly filled in the correct field
- Launch scan page appears
- Successful redirect to Scans page after scan launch
- Provider exists in Scans table (verified by organization name)
- Scan name field contains "scheduled scan"

### Notes:

- Test uses environment variables for GitHub organization name and organization access token
- Provider cleanup performed before each test to ensure clean state
- Requires valid GitHub organization with organization access token
- Organization access token must have sufficient permissions for security scanning
- Test validates that organization personal access token goes to the correct field

---

## Test Case: `PROVIDER-E2E-011` - Add AWS Provider with Assume Role via AWS SDK Defaults

**Priority:** `critical`

**Tags:**

- type → @e2e, @serial
- feature → @providers
- provider → @aws

**Description/Objective:** Validates adding an AWS provider assuming a role while sourcing credentials from the AWS SDK default chain.

**Preconditions:**

- Admin user authentication required (admin.auth.setup setup)
- Environment variables configured: E2E_AWS_PROVIDER_ROLE_ARN
- Remove any existing provider with the same Account ID before starting the test
- This test must be run serially and never in parallel with other tests, as it requires the Account ID not to be already registered beforehand

### Flow Steps:

1. Navigate to providers page
2. Click "Add Provider" button
3. Select AWS provider type
4. Fill provider details (account ID and alias)
5. Select "role" authentication type
6. Switch authentication method to "Use AWS SDK default credentials"
7. Fill role ARN using AWS SDK credential inputs
8. Launch initial scan
9. Verify redirect to Scans page
10. Verify scheduled scan status in Scans table (provider exists and scan name is "scheduled scan")

### Expected Result:

- AWS provider successfully added using AWS SDK default credentials to assume the role
- Initial scan launched successfully
- User redirected to Scans page
- Scheduled scan appears in Scans table with correct provider and scan name

### Key verification points:

- Provider page loads correctly
- Connect account page displays AWS option
- Credentials form exposes AWS SDK default authentication method
- Role ARN field accepts provided value when SDK method is selected
- Launch scan page appears
- Successful redirect to Scans page after scan launch
- Provider exists in Scans table (verified by account ID)
- Scan name field contains "scheduled scan"

### Notes:

- Test leverages AWS SDK default credential chain (environment-configured keys) for Access Key and Secret Key
- Environment variable `E2E_AWS_PROVIDER_ROLE_ARN` must reference a valid assumable role
- Provider cleanup performed before each test to ensure clean state
- Requires valid AWS account with permissions to assume the target role

---

## Test Case: `PROVIDER-E2E-012` - Add OCI Provider with API Key Credentials

**Priority:** `critical`

**Tags:**

- type → @e2e, @serial
- feature → @providers
- provider → @oci

**Description/Objective:** Validates the complete flow of adding a new OCI provider using API Key credentials.

**Preconditions:**

- Admin user authentication required (admin.auth.setup setup)
- Environment variables configured: E2E_OCI_TENANCY_ID, E2E_OCI_USER_ID, E2E_OCI_FINGERPRINT, E2E_OCI_KEY_CONTENT, E2E_OCI_REGION
- Remove any existing provider with the same Tenancy ID before starting the test
- This test must be run serially and never in parallel with other tests, as it requires the Tenancy ID not to be already registered beforehand.

### Flow Steps:

1. Navigate to providers page
2. Click "Add Provider" button
3. Select OCI provider type
4. Fill provider details (tenancy ID and alias)
5. Verify OCI credentials page is loaded
6. Fill OCI credentials (user ID, fingerprint, key content, region)
7. Launch initial scan
8. Verify redirect to Scans page
9. Verify scheduled scan status in Scans table (provider exists and scan name is "scheduled scan")

### Expected Result:

- OCI provider successfully added with API Key credentials
- Initial scan launched successfully
- User redirected to Scans page
- Scheduled scan appears in Scans table with correct provider and scan name

### Key verification points:

- Provider page loads correctly
- Connect account page displays OCI option
- Provider details form accepts tenancy ID and alias
- OCI credentials page loads
- Credentials form accepts all required fields (user ID, fingerprint, key content, region)
- Launch scan page appears
- Successful redirect to Scans page after scan launch
- Provider exists in Scans table (verified by tenancy ID)
- Scan name field contains "scheduled scan"

### Notes:

- Test uses environment variables for OCI credentials
- Provider cleanup performed before each test to ensure clean state
- Requires valid OCI account with API Key set up
- API Key credential type is automatically used for OCI providers

---

## Test Case: `PROVIDER-E2E-013` - Update OCI Provider Credentials

**Priority:** `normal`

**Tags:**

- type → @e2e, @serial
- feature → @providers
- provider → @oci

**Description/Objective:** Validates the complete flow of updating credentials for an existing OCI provider. This test verifies that the provider UID is correctly passed to the update credentials form, which is required for OCI credential validation.

**Preconditions:**

- Admin user authentication required (admin.auth.setup setup)
- Environment variables configured: E2E_OCI_TENANCY_ID, E2E_OCI_USER_ID, E2E_OCI_FINGERPRINT, E2E_OCI_KEY_CONTENT, E2E_OCI_REGION
- An OCI provider with the specified Tenancy ID must already exist (run PROVIDER-E2E-012 first)
- This test must be run serially and never in parallel with other tests

### Flow Steps:

1. Navigate to providers page
2. Verify OCI provider exists in the table
3. Click row actions menu for the OCI provider
4. Click "Update Credentials" option
5. Verify update credentials page is loaded
6. Verify OCI credentials form fields are visible (confirms providerUid is loaded)
7. Fill OCI credentials (user ID, fingerprint, key content, region)
8. Click Next to submit
9. Verify successful navigation to test connection page

### Expected Result:

- Update credentials page loads successfully
- OCI credentials form is displayed with all required fields
- Provider UID is correctly passed to the form (hidden field populated)
- Credentials can be updated and submitted
- User is redirected to test connection page after successful update

### Key verification points:

- Provider page loads correctly
- OCI provider row is visible in providers table
- Row actions dropdown opens and displays "Update Credentials" option
- Update credentials page URL contains correct parameters
- OCI credentials form displays all fields (tenancy ID, user ID, fingerprint, key content, region)
- Form submission succeeds (no silent failures due to missing provider UID)
- Successful redirect to test connection page

### Notes:

- Test uses same environment variables as PROVIDER-E2E-012 (add OCI provider)
- Requires PROVIDER-E2E-012 to be run first to create the OCI provider
- This test validates the fix for OCI update credentials form failing silently due to missing provider UID
- The provider UID is required for OCI credential validation (tenancy field auto-populated from UID)

---

## Test Case: `PROVIDER-E2E-014` - Add AlibabaCloud Provider with Static Credentials

**Priority:** `critical`

**Tags:**

- type → @e2e, @serial
- feature → @providers
- provider → @alibabacloud

**Description/Objective:** Validates the complete flow of adding a new Alibaba Cloud provider using static credentials (Access Key ID and Access Key Secret)

**Preconditions:**

- Admin user authentication required (admin.auth.setup setup)
- Environment variables configured: E2E_ALIBABACLOUD_ACCOUNT_ID, E2E_ALIBABACLOUD_ACCESS_KEY_ID, E2E_ALIBABACLOUD_ACCESS_KEY_SECRET
- Remove any existing provider with the same Account ID before starting the test
- This test must be run serially and never in parallel with other tests, as it requires the Account ID not to be already registered beforehand.

### Flow Steps:

1. Navigate to providers page
2. Click "Add Provider" button
3. Select AlibabaCloud provider type
4. Fill provider details (account ID and alias)
5. Verify AlibabaCloud credentials page is loaded
6. Select static credentials type
7. Verify static credentials page is loaded
8. Fill AlibabaCloud credentials (access key ID and access key secret)
9. Launch initial scan
10. Verify redirect to Scans page
11. Verify scheduled scan status in Scans table (provider exists and scan name is "scheduled scan")

### Expected Result:

- AlibabaCloud provider successfully added with static credentials
- Initial scan launched successfully
- User redirected to Scans page
- Scheduled scan appears in Scans table with correct provider and scan name

### Key verification points:

- Provider page loads correctly
- Connect account page displays AlibabaCloud option
- Provider details form accepts account ID and alias
- Credentials page loads with credential type selection
- Static credentials page loads with access key ID and access key secret fields
- Static credentials are properly filled in the correct fields
- Launch scan page appears
- Successful redirect to Scans page after scan launch
- Provider exists in Scans table (verified by account ID)
- Scan name field contains "scheduled scan"

### Notes:

- Test uses environment variables for AlibabaCloud credentials
- Provider cleanup performed before each test to ensure clean state
- Requires valid Alibaba Cloud account with appropriate permissions
- Static credentials must have sufficient permissions for security scanning

---

## Test Case: `PROVIDER-E2E-015` - Add AlibabaCloud Provider with RAM Role Credentials

**Priority:** `critical`

**Tags:**

- type → @e2e, @serial
- feature → @providers
- provider → @alibabacloud

**Description/Objective:** Validates the complete flow of adding a new Alibaba Cloud provider using RAM Role credentials (Access Key ID, Access Key Secret, and Role ARN)

**Preconditions:**

- Admin user authentication required (admin.auth.setup setup)
- Environment variables configured: E2E_ALIBABACLOUD_ACCOUNT_ID, E2E_ALIBABACLOUD_ACCESS_KEY_ID, E2E_ALIBABACLOUD_ACCESS_KEY_SECRET, E2E_ALIBABACLOUD_ROLE_ARN
- Remove any existing provider with the same Account ID before starting the test
- This test must be run serially and never in parallel with other tests, as it requires the Account ID not to be already registered beforehand.

### Flow Steps:

1. Navigate to providers page
2. Click "Add Provider" button
3. Select AlibabaCloud provider type
4. Fill provider details (account ID and alias)
5. Verify AlibabaCloud credentials page is loaded
6. Select RAM Role credentials type
7. Verify RAM Role credentials page is loaded
8. Fill AlibabaCloud RAM Role credentials (access key ID, access key secret, and role ARN)
9. Launch initial scan
10. Verify redirect to Scans page
11. Verify scheduled scan status in Scans table (provider exists and scan name is "scheduled scan")

### Expected Result:

- AlibabaCloud provider successfully added with RAM Role credentials
- Initial scan launched successfully
- User redirected to Scans page
- Scheduled scan appears in Scans table with correct provider and scan name

### Key verification points:

- Provider page loads correctly
- Connect account page displays AlibabaCloud option
- Provider details form accepts account ID and alias
- Credentials page loads with credential type selection
- RAM Role credentials page loads with access key ID, access key secret, and role ARN fields
- RAM Role credentials are properly filled in the correct fields
- Launch scan page appears
- Successful redirect to Scans page after scan launch
- Provider exists in Scans table (verified by account ID)
- Scan name field contains "scheduled scan"

### Notes:

- Test uses environment variables for AlibabaCloud RAM Role credentials
- Provider cleanup performed before each test to ensure clean state
- Requires valid Alibaba Cloud account with RAM Role configured
- RAM Role must have sufficient permissions for security scanning
- Role ARN must be properly configured and assumable

---

## Test Case: `PROVIDER-E2E-016` - Add AWS Organization Using AWS Organizations Flow

**Priority:** `critical`

**Tags:**

- type → @e2e, @serial
- feature → @providers
- provider → @aws

**Description/Objective:** Validates the complete flow of adding AWS accounts through AWS Organizations, including organization setup, authentication, account selection, and scan scheduling.

**Preconditions:**

- Admin user authentication required (admin.auth.setup setup)
- Environment variables configured: E2E_AWS_ORGANIZATION_ID, E2E_AWS_ORGANIZATION_ROLE_ARN
- Remove any existing provider with the same Organization ID before starting the test
- StackSet must be deployed in AWS Organizations and expose a valid IAM Role ARN for Prowler
- This test must be run serially and never in parallel with other tests, as it requires the Organization ID not to be already registered beforehand.

### Flow Steps:

1. Navigate to providers page
2. Click "Add Provider" button
3. Select AWS provider type
4. Select "Add Multiple Accounts With AWS Organizations"
5. Fill organization details (organization ID and optional name)
6. Continue to authentication details and provide role ARN
7. Confirm StackSet deployment checkbox and authenticate
8. Confirm organization account selection step and continue
9. Verify organization launch step, choose single scan schedule, and launch
10. Verify redirect to Scans page

### Expected Result:

- AWS Organizations flow completes successfully
- Accounts are connected and launch step is displayed
- Scan scheduling selection is applied
- User is redirected to Scans page after launch

### Key verification points:

- Connect account page displays AWS option
- Organizations method selector is available
- Authentication details step loads
- Account selection step loads
- Accounts connected launch step appears
- Successful redirect to Scans page after launching

### Notes:

- Organization ID must follow AWS format (e.g., o-abc123def4)
- Role ARN must belong to the StackSet deployment for Organizations flow
- Provider cleanup is executed before test run to avoid unique constraint conflicts
