## Deployment using Terraform

This Terraform configuration creates the necessary IAM role and policies to allow Prowler to scan your AWS account, with optional S3 integration for storing scan reports.

### Quick Start

1. **Configure variables:**
   ```bash
   cp terraform.tfvars.example terraform.tfvars
   # Edit terraform.tfvars with your values
   ```

2. **Deploy:**
   ```bash
   terraform init
   terraform plan
   terraform apply
   ```

### Variables

- `external_id` (required): External ID for role assumption security
- `account_id` (optional): AWS Account ID that will assume the role (defaults to Prowler Cloud: "232136659152")
- `iam_principal` (optional): IAM principal pattern allowed to assume the role (defaults to Prowler Cloud: "role/prowler*")
- `enable_s3_integration` (optional): Enable S3 integration for storing scan reports (default: false)
- `s3_integration_bucket_name` (conditional): S3 bucket name for reports (required if `enable_s3_integration` is true)
- `s3_integration_bucket_account_id` (conditional): S3 bucket owner account ID (required if `enable_s3_integration` is true)
- `enable_realtime_detection` (optional): Forward the tracked CloudTrail management events to Prowler Cloud through an EventBridge API destination (default: false)
- `prowler_webhook_url` (optional): Prowler Cloud endpoint that receives the events (defaults to Prowler Cloud: `https://api.prowler.com/api/v1/realtime/events`; change it only for a self-hosted deployment or for testing)
- `prowler_api_key` (conditional): Prowler Cloud API key used to authenticate the events (required if `enable_realtime_detection` is true)

### Usage Examples

#### Basic deployment (without S3 integration)
```bash
terraform apply -var="external_id=your-external-id-here"
```

#### With S3 integration enabled
```bash
terraform apply \
  -var="external_id=your-external-id-here" \
  -var="enable_s3_integration=true" \
  -var="s3_integration_bucket_name=your-s3-bucket-name" \
  -var="s3_integration_bucket_account_id=123456789012"
```

#### With real-time detection enabled
```bash
terraform apply \
  -var="external_id=your-external-id-here" \
  -var="enable_realtime_detection=true" \
  -var="prowler_api_key=your-prowler-api-key-here"
```

`prowler_webhook_url` already defaults to the Prowler Cloud ingest endpoint, so only the API key is needed. Override it for a self-hosted deployment or for testing.

> **Note:** the EventBridge rule is regional. It forwards only the events delivered to the default event bus of the region Terraform deploys to (`us-east-1` by default, see `versions.tf`). IAM events are global and always land in `us-east-1`, but regional services (EC2 security groups, RDS, per-region Config and GuardDuty) are only covered in that region. Deploy the module in every region you want covered.

#### Using terraform.tfvars file (Recommended)
```bash
cp terraform.tfvars.example terraform.tfvars
# Edit the file with your values
terraform apply
```

#### Command line variables (Alternative)
```bash
terraform apply -var="external_id=your-external-id-here"
```

### Outputs

After successful deployment, you'll get:
- `prowler_role_arn`: The ARN of the created IAM role (use this in Prowler App)
- `prowler_role_name`: The name of the IAM role
- `s3_integration_enabled`: Whether S3 integration is enabled
- `realtime_detection_enabled`: Whether real-time detection is enabled
- `prowler_realtime_rule_arn`: ARN of the EventBridge rule (null if real-time detection is disabled)
- `prowler_realtime_api_destination_arn`: ARN of the EventBridge API destination (null if real-time detection is disabled)

> **Note:** Terraform will use the AWS credentials of your default profile or AWS_PROFILE environment variable.
