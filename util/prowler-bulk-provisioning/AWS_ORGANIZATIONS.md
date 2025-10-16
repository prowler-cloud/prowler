# AWS Organizations Integration Guide

Automated YAML configuration generator for bulk-provisioning all accounts in an AWS Organization.

## Overview

The `aws_org_generator.py` script simplifies provisioning multiple AWS accounts by automatically discovering all accounts in your organization and generating the YAML configuration needed for the bulk provisioning tool.

## Prerequisites

### 1. Deploy ProwlerRole Across All Accounts

Before using this tool, you must deploy the ProwlerRole (or custom role) across all accounts in your organization using CloudFormation StackSets.

**Follow the official documentation:**
[Deploying Prowler IAM Roles Across AWS Organizations](https://docs.prowler.com/projects/prowler-open-source/en/latest/tutorials/aws/organizations/#deploying-prowler-iam-roles-across-aws-organizations)

**Key points:**
- Use CloudFormation StackSets from the management account
- Deploy to all organizational units (OUs) or specific OUs
- Use an external ID for enhanced security
- Ensure the role has the necessary permissions for Prowler scans

### 2. AWS Credentials with Organizations Access

You need AWS credentials with permissions to list organization accounts. Typically, this means:

- **Using the management account credentials**, or
- **A delegated administrator account** with `organizations:ListAccounts` permission

Required IAM permissions:
```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "organizations:ListAccounts",
        "organizations:DescribeOrganization"
      ],
      "Resource": "*"
    }
  ]
}
```

### 3. Install Dependencies

```bash
pip install -r requirements-aws-org.txt
```

This installs:
- boto3 (AWS SDK)
- PyYAML (YAML parsing)
- requests (HTTP client)

## Basic Usage

### Generate Configuration for All Accounts

```bash
python aws_org_generator.py -o aws-accounts.yaml --external-id prowler-ext-id-2024
```

This will:
1. List all ACTIVE accounts in your organization
2. Generate YAML entries for each account
3. Save to `aws-accounts.yaml`

### Run Bulk Provisioning

```bash
python prowler_bulk_provisioning.py aws-accounts.yaml
```

## Advanced Usage

### Using a Specific AWS Profile

```bash
python aws_org_generator.py \
  -o aws-accounts.yaml \
  --profile org-management-admin \
  --external-id prowler-ext-id-2024
```

### Excluding Specific Accounts

Exclude the management account or other accounts you don't want to scan:

```bash
python aws_org_generator.py \
  -o aws-accounts.yaml \
  --external-id prowler-ext-id-2024 \
  --exclude 123456789012,210987654321
```

### Including Only Specific Accounts

Only generate configuration for specific accounts:

```bash
python aws_org_generator.py \
  -o aws-accounts.yaml \
  --external-id prowler-ext-id-2024 \
  --include 111111111111,222222222222,333333333333
```

### Custom Role Name

If you deployed a custom role name instead of `ProwlerRole`:

```bash
python aws_org_generator.py \
  -o aws-accounts.yaml \
  --role-name ProwlerExecutionRole \
  --external-id prowler-ext-id-2024
```

### Custom Alias Format

Customize how account aliases are generated using template variables:

```bash
# Use account name and ID
python aws_org_generator.py \
  -o aws-accounts.yaml \
  --alias-format "{name}-{id}" \
  --external-id prowler-ext-id-2024

# Use email prefix
python aws_org_generator.py \
  -o aws-accounts.yaml \
  --alias-format "{email}" \
  --external-id prowler-ext-id-2024
```

Available template variables:
- `{name}` - Account name
- `{id}` - Account ID
- `{email}` - Account email

### Dry Run Mode

Preview the configuration without writing a file:

```bash
python aws_org_generator.py \
  --external-id prowler-ext-id-2024 \
  --dry-run
```

## Complete Workflow Example

### Step 1: Deploy ProwlerRole Using StackSets

1. Log into your AWS management account
2. Navigate to CloudFormation → StackSets
3. Create a new StackSet using the Prowler role template
4. Deploy to all organizational units
5. Use a unique external ID (e.g., `prowler-org-2024-abc123`)

### Step 2: Generate YAML Configuration

```bash
# Using management account credentials
export AWS_PROFILE=org-management

# Generate configuration
python aws_org_generator.py \
  -o aws-org-accounts.yaml \
  --external-id prowler-org-2024-abc123 \
  --exclude 123456789012
```

**Output:**
```
Fetching accounts from AWS Organizations...
Using AWS profile: org-management
Found 47 active accounts in organization
Generated configuration for 46 accounts

Configuration written to: aws-org-accounts.yaml

Next steps:
  1. Review the generated file: cat aws-org-accounts.yaml | head -n 20
  2. Run bulk provisioning: python prowler_bulk_provisioning.py aws-org-accounts.yaml
```

### Step 3: Review Generated Configuration

```bash
head -n 20 aws-org-accounts.yaml
```

### Step 4: Run Bulk Provisioning

```bash
# Set Prowler API credentials
export PROWLER_API_TOKEN="your-prowler-api-token"

# Run bulk provisioning (with connection testing)
python prowler_bulk_provisioning.py aws-org-accounts.yaml
```

**With custom options:**
```bash
python prowler_bulk_provisioning.py aws-org-accounts.yaml \
  --concurrency 10 \
  --timeout 120
```

## Troubleshooting

### Error: "No AWS credentials found"

**Solution:** Configure AWS credentials using one of these methods:

```bash
# Method 1: AWS CLI configure
aws configure

# Method 2: Environment variables
export AWS_ACCESS_KEY_ID=your-key-id
export AWS_SECRET_ACCESS_KEY=your-secret-key

# Method 3: Use AWS profile
export AWS_PROFILE=org-management
```

### Error: "Access denied to AWS Organizations API"

**Cause:** Current credentials don't have permission to list organization accounts.

**Solution:**
- Ensure you're using management account credentials
- Verify IAM permissions include `organizations:ListAccounts`

### Error: "AWS Organizations is not enabled"

**Cause:** The account is not part of an organization.

**Solution:** This tool requires an AWS Organization. Create one in the AWS Organizations console.

### No Accounts Generated After Filters

**Cause:** All accounts were filtered out by `--exclude` or `--include` options.

**Solution:** Review your filter options and verify account IDs are correct.

## Security Best Practices

### Use External ID

Always use an external ID when assuming cross-account roles:

```bash
python aws_org_generator.py \
  -o aws-accounts.yaml \
  --external-id $(uuidgen | tr '[:upper:]' '[:lower:]')
```

The external ID must match the one configured in the ProwlerRole trust policy.

### Exclude Sensitive Accounts

Exclude accounts that shouldn't be scanned:

```bash
python aws_org_generator.py \
  -o aws-accounts.yaml \
  --external-id prowler-ext-id \
  --exclude 123456789012,111111111111  # management, break-glass accounts
```

### Review Generated Configuration

Always review the generated YAML before provisioning:

```bash
# Check for unexpected accounts
grep "uid:" aws-org-accounts.yaml

# Verify role ARNs
grep "role_arn:" aws-org-accounts.yaml | head -5

# Count accounts
grep "provider: aws" aws-org-accounts.yaml | wc -l
```

## Command Reference

### Full Command-Line Options

```bash
python aws_org_generator.py \
  -o OUTPUT_FILE \
  --role-name ROLE_NAME \
  --external-id EXTERNAL_ID \
  --session-name SESSION_NAME \
  --duration-seconds SECONDS \
  --alias-format FORMAT \
  --exclude ACCOUNT_IDS \
  --include ACCOUNT_IDS \
  --profile AWS_PROFILE \
  --region AWS_REGION \
  --dry-run
```

### Help Output

```bash
python aws_org_generator.py --help
```

## Support

For issues or questions:
1. [Prowler Documentation](https://docs.prowler.com)
2. [Prowler GitHub Issues](https://github.com/prowler-cloud/prowler/issues)
3. [Prowler Community Slack](https://prowler.com/slack)
