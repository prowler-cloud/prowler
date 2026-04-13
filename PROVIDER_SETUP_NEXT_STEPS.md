# Prowler Cloud.gov Provider Setup - Next Steps

**Date**: April 13, 2026  
**Status**: Applications stopped, ready for provider configuration  
**Org**:  
**Space**: 

## Current System Status

✅ **Stopped Applications**:
- `prowler-ui` - stopped
- `prowler-api-web` - stopped

🔄 **Running (Background)**:
- `prowler-api-beat` - Celery beat scheduler
- `prowler-api-worker` - Celery worker

❌ **Provider Status**:
- AWS - Missing credentials
- GCP - Credentials need verification
- Azure - Missing credentials

---

## Provider Configuration Checklist

Before restarting the applications, you need to configure credentials for each cloud provider. This document provides explicit step-by-step instructions.

### Prerequisites
- [ ] Access to AWS account 144433228153 (18F Enterprise)
- [ ] GCP service account JSON for project `tts-datagov` (already provided)
- [ ] Access to Azure subscription 22d1089a-8f68-49ca-bf93-2fe5233cfd51 (tts-sandbox)
- [ ] Cloud.gov CLI logged in: `cf target -o gsa-10x-prototyping -s tts-pic-dev`

---

## Option A: Quick Start - Update Secrets via UI (Recommended for Testing)

This method updates credentials directly in the database through the UI. Use this for initial testing.

### Step 1: Start Applications Temporarily
```bash
cd /Users/johnhjediny/Documents/GitHub/prowler

# Start API first
cf start prowler-api-web

# Wait for API to be healthy (30-60 seconds)
sleep 60
cf app prowler-api-web

# Start UI
cf start prowler-ui

# Verify both are running
cf apps | grep prowler
```

### Step 2: Access Prowler UI
1. Open browser: https://prowler-ui-gsa-10x-prototyping.app.cloud.gov
2. Login with UAA: john.jediny@gsa.gov
3. Navigate to: Configuration > Cloud Providers

### Step 3: Configure AWS Provider

#### 3a. Create AWS IAM User (One-time Setup)

**In AWS Console (account 144433228153)**:

1. Go to IAM Console: https://console.aws.amazon.com/iam/
2. Navigate to: Users > Create user
   - User name: `prowler-scanner`
   - AWS credential type: ✅ Access key - Programmatic access
   - Click: Next

3. Set Permissions:
   - Attach policies directly:
     - ✅ `SecurityAudit` (AWS managed policy)
     - ✅ `ViewOnlyAccess` (AWS managed policy)
   - Click: Next > Create user

4. **IMPORTANT**: Save credentials immediately (they'll only show once):
   ```
   Access Key ID: AKIA........................
   Secret Access Key: ........................................
   ```

5. Optional but recommended - Add MFA to the user for additional security

#### 3b. Update Prowler with AWS Credentials

**In Prowler UI**:

1. Find provider: `18F Enterprise` (AWS)
2. Click: ⚙️ Settings icon > Edit Credentials
3. Choose authentication method: **Static Credentials**
4. Fill in the form:
   ```
   AWS Access Key ID: [paste from step 4 above]
   AWS Secret Access Key: [paste from step 4 above]
   ```
5. Click: **Save**
6. Click: **Test Connection**
7. Verify: Status shows "✅ Connected"

**Expected Result**:
- Connection status: ✅ Connected
- Last checked: [current timestamp]

**If connection fails**, check:
```bash
# View API logs for detailed error
cf logs prowler-api-web --recent | grep -A 10 "AWS\|connection"
```

Common issues:
- ❌ "Invalid credentials" → Double-check access key ID and secret
- ❌ "Access denied" → Verify SecurityAudit + ViewOnlyAccess policies attached
- ❌ "STS endpoint not active" → Enable EU (Ireland) endpoint in AWS account settings

### Step 4: Configure GCP Provider

You've already provided the service account JSON file: `tts-datagov-f7fef7e76ec8.json`

#### 4a. Verify Service Account Permissions (One-time Setup)

**In GCP Console (project tts-datagov)**:

1. Go to: https://console.cloud.google.com/iam-admin/iam?project=tts-datagov
2. Find service account: Look for the email from your JSON file
   - Should be: `[something]@tts-datagov.iam.gserviceaccount.com`
3. Verify it has role: **Security Reviewer** or **Viewer**

**If role is missing**, add it:
```bash
# Get the service account email from your JSON
SERVICE_ACCOUNT=$(cat tts-datagov-f7fef7e76ec8.json | jq -r '.client_email')

# Add Security Reviewer role
gcloud projects add-iam-policy-binding tts-datagov \
  --member="serviceAccount:${SERVICE_ACCOUNT}" \
  --role="roles/iam.securityReviewer"
```

#### 4b. Update Prowler with GCP Credentials

**In Prowler UI**:

1. Find provider: `` (GCP)
2. Click: ⚙️ Settings icon > Edit Credentials
3. Choose authentication method: **Service Account JSON**
4. **Paste entire JSON file contents**:
   ```bash
   # Copy the file to clipboard (macOS)
   cat tts-datagov-f7fef7e76ec8.json | pbcopy
   ```
5. Paste into the credentials field
6. Click: **Save**
7. Click: **Test Connection**
8. Verify: Status shows "✅ Connected"

**Expected Result**:
- Connection status: ✅ Connected
- Project ID: tts-datagov verified

**If connection fails**, check:
```bash
# View logs
cf logs prowler-api-web --recent | grep -A 10 "GCP\|connection"

# Validate JSON locally
cat tts-datagov-f7fef7e76ec8.json | jq '.'
# Should show no errors and include: type, project_id, private_key, client_email
```

Common issues:
- ❌ "Invalid service account" → Verify JSON is complete and valid
- ❌ "API not enabled" → Enable required APIs in GCP Console
- ❌ "Permission denied" → Add Security Reviewer role (step 4a)

### Step 5: Configure Azure Provider

#### 5a. Create Azure Service Principal (One-time Setup)

**Method 1: Azure Portal (GUI)**

1. Go to: https://portal.azure.com
2. Navigate to: Azure Active Directory (Entra ID) > App registrations
3. Click: **+ New registration**
   - Name: `prowler-scanner`
   - Supported account types: Single tenant
   - Redirect URI: (leave blank)
   - Click: **Register**

4. **Save these values immediately**:
   - Application (client) ID: `xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx`
   - Directory (tenant) ID: `xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx`

5. Create client secret:
   - In app registration, go to: Certificates & secrets
   - Click: + New client secret
   - Description: `prowler-scanner-key`
   - Expires: 24 months (or max allowed)
   - Click: **Add**
   - **IMPORTANT**: Copy the secret VALUE immediately (only shown once)

6. Assign subscription permissions:
   - Go to: Subscriptions > tts-sandbox ()
   - Click: Access control (IAM) > + Add role assignment
   - Role: **Reader** → Select `prowler-scanner` → Save
   - Repeat for: **Security Reader** → Select `prowler-scanner` → Save

7. Assign directory permissions:
   - Go back to: Azure Active Directory (Entra ID) > Roles and administrators
   - Search for: **Directory Readers**
   - Click: + Add assignments > Select `prowler-scanner` → Add

**Method 2: Azure CLI (Command Line)**

```bash
# Login
az login

# Set subscription
az account set --subscription "################"

# Create service principal
az ad sp create-for-rbac --name "prowler-scanner" \
  --role "Reader" \
  --scopes "/subscriptions/###############"

# Output will show:
{
  "appId": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",  # This is CLIENT_ID
  "displayName": "prowler-scanner",
  "password": "xxxxxxxxxxxxxxxxxxxxxxxxxxxx",       # This is CLIENT_SECRET
  "tenant": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"  # This is TENANT_ID
}

# Add Security Reader role
az role assignment create \
  --assignee [appId from above] \
  --role "Security Reader" \
  --scope "/subscriptions/################"

# Add Directory Reader role
az ad directory-role member add \
  --role "Directory Readers" \
  --member-id [objectId of service principal]
```

#### 5b. Update Prowler with Azure Credentials

**In Prowler UI**:

1. Find provider: `tts-sandbox` (Azure)
2. Click: ⚙️ Settings icon > Edit Credentials
3. Choose authentication method: **Service Principal**
4. Fill in the form:
   ```
   Tenant ID: [from step 5a]
   Client ID: [from step 5a]
   Client Secret: [from step 5a]
   ```
5. Click: **Save**
6. Click: **Test Connection**
7. Verify: Status shows "✅ Connected"

**Expected Result**:
- Connection status: ✅ Connected
- Subscription: ################ verified

**If connection fails**, check:
```bash
# View logs
cf logs prowler-api-web --recent | grep -A 10 "Azure\|connection"
```

Common issues:
- ❌ "AADSTS700016: Application not found" → Verify Client ID is correct
- ❌ "Client secret expired" → Generate new secret in Azure Portal
- ❌ "Insufficient privileges" → Verify Reader + Security Reader + Directory Reader roles

---

## Option B: Production Setup - VCAP_SERVICES (Recommended for Deployment)

This method uses Cloud.gov's native service binding pattern for secure credential management.

### Step 1: Create User-Provided Services

#### AWS Service
```bash
# Create credentials file
cat > aws-credentials.json <<'EOF'
{
  "aws_access_key_id": "AKIA.....................",
  "aws_secret_access_key": "........................................"
}
EOF

# Create service
cf create-user-provided-service prowler-aws-profile -p aws-credentials.json

# Secure cleanup
rm aws-credentials.json
```

#### GCP Service
```bash
# You already have: tts-datagov-f7fef7e76ec8.json
cf create-user-provided-service prowler-gcp-tts-datagov -p tts-datagov-f7fef7e76ec8.json
```

#### Azure Service
```bash
# Create credentials file
cat > azure-credentials.json <<'EOF'
{
  "tenant_id": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
  "client_id": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
  "client_secret": "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
}
EOF

# Create service
cf create-user-provided-service prowler-azure-tts-sandbox -p azure-credentials.json

# Secure cleanup
rm azure-credentials.json
```

### Step 2: Bind Services to API
```bash
# Bind all three services
cf bind-service prowler-api-web prowler-aws-profile
cf bind-service prowler-api-web prowler-gcp-profile
cf bind-service prowler-api-web prowler-azure-profile

# Verify bindings
cf services
```

### Step 3: Update API Code (FUTURE - Not Yet Implemented)

**Note**: The VCAP_SERVICES integration code is documented in `PROVIDER_CONNECTION_IMPLEMENTATION_PLAN.md` but not yet implemented. For now, use **Option A** (UI-based configuration).

To implement VCAP_SERVICES support, follow Phase 2 in the implementation plan:
1. Create `api/src/backend/config/vcap.py`
2. Modify `api/src/backend/api/utils.py:get_prowler_provider_kwargs()`
3. Deploy updated code
4. Restage: `cf restage prowler-api-web`

---

## Verification Steps

After configuring all providers:

### 1. Check Provider Status in UI
```
Configuration > Cloud Providers
- AWS: ✅ Connected
- GCP: ✅ Connected
- Azure: ✅ Connected
```

### 2. Test a Security Scan

**In Prowler UI**:
1. Go to: Scans > New Scan
2. Select provider: AWS - 18F Enterprise
3. Choose scan type: Quick Scan (recommended for first test)
4. Click: **Start Scan**
5. Monitor progress in: Scans > Active Scans

**Expected**: Scan starts and shows progress

### 3. Check API Logs for Errors
```bash
# Watch live logs
cf logs prowler-api-web

# In another terminal, trigger a connection test in UI
# Look for successful connection messages like:
# "Connection test passed for provider aws:144433228153"
```

### 4. Verify Database Records
```bash
# SSH into API container
cf ssh prowler-api-web

# Run Django shell
export LD_LIBRARY_PATH=/home/vcap/deps/0/lib
/home/vcap/deps/0/bin/python /home/vcap/app/manage.py shell

# In Python shell:
from api.models import Provider
providers = Provider.objects.filter(provider__in=['aws', 'azure', 'gcp'])
for p in providers:
    print(f"{p.provider}: {p.connected} (last checked: {p.connection_last_checked_at})")
# Should show: True for all three
```

---

## Restart Procedures

### Standard Restart (After Configuration)
```bash
cd /Users/johnhjediny/Documents/GitHub/prowler

# Start API
cf start prowler-api-web

# Wait for health check
sleep 60

# Verify API is healthy
cf app prowler-api-web
# Should show: state: started, instances: 1/1

# Start UI
cf start prowler-ui

# Wait for health check
sleep 30

# Verify UI is healthy
cf app prowler-ui
# Should show: state: started, instances: 1/1

# Open application
open https://prowler-ui-gsa-10x-prototyping.app.cloud.gov
```

### Health Check Commands
```bash
# Check all instances
cf apps | grep prowler

# Check logs for errors
cf logs prowler-api-web --recent | grep ERROR
cf logs prowler-ui --recent | grep ERROR

# Check API health endpoint
curl https://prowler-api-gsa-10x-prototyping.app.cloud.gov/health
# Should return: {"status": "healthy"}

# Check UI
curl -I https://prowler-ui-gsa-10x-prototyping.app.cloud.gov
# Should return: HTTP/2 200
```

---

## Troubleshooting Guide

### Issue: Apps won't start
```bash
# Check recent logs
cf logs prowler-api-web --recent

# Common fixes:
cf restage prowler-api-web  # Rebuild container
cf restart prowler-api-web  # Force restart
```

### Issue: Provider connection test fails
```bash
# Check specific provider logs
cf logs prowler-api-web --recent | grep -i "aws\|gcp\|azure" | grep -i "error\|fail"

# Check Celery worker logs (connection tests run there)
cf logs prowler-api-worker --recent | grep -i "connection"
```

### Issue: Credentials not found
```bash
# Verify secret exists in database
cf ssh prowler-api-web -c "export LD_LIBRARY_PATH=/home/vcap/deps/0/lib && /home/vcap/deps/0/bin/python /home/vcap/app/manage.py shell -c 'from api.models import Provider, ProviderSecret; print(ProviderSecret.objects.count())'"

# Should show number > 0
```

### Issue: VCAP_SERVICES not working (Option B)
```bash
# Check if services are bound
cf services | grep prowler

# View VCAP_SERVICES
cf env prowler-api-web | grep -A 50 VCAP_SERVICES

# Should show your bound services with credentials
```

---

## Security Best Practices

### 1. Credential Storage
- ✅ **Good**: VCAP_SERVICES (Option B)
- ✅ **Acceptable**: Database with Fernet encryption (Option A)
- ❌ **Bad**: Environment variables in manifest
- ❌ **Never**: Committed to Git

### 2. Permissions (Principle of Least Privilege)
- **AWS**: Only ReadOnly + SecurityAudit policies
- **GCP**: Only Security Reviewer role (not Owner/Editor)
- **Azure**: Only Reader + Security Reader (not Contributor)

### 3. Credential Rotation
Set calendar reminders:
- AWS Access Keys: Every 90 days
- GCP Service Account Keys: Yearly
- Azure Client Secrets: Before expiration date

### 4. Audit Trail
Regularly review:
```bash
# API access logs
cf logs prowler-api-web --recent | grep "POST /api/v1/providers"

# Provider modifications
cf logs prowler-api-web --recent | grep "PATCH /api/v1/providers"
```

---

## Next Development Tasks

After successful provider configuration:

1. **Test Security Scans**:
   - Run test scan on each provider
   - Verify findings appear in UI
   - Check scan performance/duration

2. **Configure Scan Schedules**:
   - Set up recurring scans
   - Configure notification preferences

3. **Implement VCAP_SERVICES** (Phase 2):
   - Follow implementation plan
   - Test credential failover
   - Document deployment process

4. **Production Hardening**:
   - Set up monitoring/alerting
   - Configure backup/restore procedures
   - Implement credential rotation automation

---

## Support Resources

### Documentation
- Prowler Docs: https://docs.prowler.com
- Cloud.gov Docs: https://cloud.gov/docs
- AWS IAM: https://docs.aws.amazon.com/iam/
- GCP IAM: https://cloud.google.com/iam/docs
- Azure RBAC: https://learn.microsoft.com/azure/role-based-access-control/

### Internal Contacts
- Cloud.gov Support: support@cloud.gov
- GSA AWS Team: [internal contact]
- TTS GCP Team: [internal contact]
- TTS Azure Team: [internal contact]

### Emergency Procedures
If something goes wrong:
```bash
# Stop everything
cf stop prowler-ui
cf stop prowler-api-web

# Check logs
cf logs prowler-api-web --recent > /tmp/api-logs.txt
cf logs prowler-ui --recent > /tmp/ui-logs.txt

# Contact support with logs
```

---

## Completion Checklist

Before marking provider setup as complete:

- [ ] AWS provider shows "Connected" status
- [ ] GCP provider shows "Connected" status  
- [ ] Azure provider shows "Connected" status
- [ ] Test scan completes successfully on AWS
- [ ] Test scan completes successfully on GCP
- [ ] Test scan completes successfully on Azure
- [ ] All credentials documented securely (1Password/Vault)
- [ ] Credential rotation calendar entries created
- [ ] Team trained on restart procedures
- [ ] Monitoring/alerting configured
- [ ] Production deployment documented

---

**Last Updated**: April 13, 2026  
**Document Version**: 1.0  
**Owner**: John Jediny  
**Status**: Ready for provider configuration
