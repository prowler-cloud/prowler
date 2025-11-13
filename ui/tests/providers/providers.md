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
8. Verify redirect to provider management page

### Expected Result:

- M365 provider successfully added with static credentials
- Initial scan launched successfully
- User redirected to provider details page

### Key verification points:

- Provider page loads correctly
- Connect account page displays M365 option
- M365 credentials form accepts all required fields
- Launch scan page appears
- Successful redirect to provider page after scan launch

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
8. Verify redirect to provider management page

### Expected Result:

- M365 provider successfully added with certificate credentials
- Initial scan launched successfully
- User redirected to provider details page

### Key verification points:

- Provider page loads correctly
- Connect account page displays M365 option
- Certificate credentials form accepts all required fields
- Launch scan page appears
- Successful redirect to provider page after scan launch

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
8. Verify redirect to provider management page

### Expected Result:

- Kubernetes provider successfully added with kubeconfig content
- Initial scan launched successfully
- User redirected to provider details page

### Key verification points:

- Provider page loads correctly
- Connect account page displays Kubernetes option
- Provider details form accepts context and alias
- Credentials page loads with kubeconfig content field
- Kubeconfig content is properly filled in the correct field
- Launch scan page appears
- Successful redirect to provider page after scan launch

### Notes:

- Test uses environment variables for Kubernetes context and kubeconfig file path
- Kubeconfig content is read from file and used for authentication
- Provider cleanup performed before each test to ensure clean state
- Requires valid Kubernetes cluster with accessible kubeconfig
- Kubeconfig must have sufficient permissions for security scanning
- Test validates that kubeconfig content goes to the correct field (not the context field)
