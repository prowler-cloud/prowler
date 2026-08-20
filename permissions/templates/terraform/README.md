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
- `region` (optional): AWS region to deploy to (default: `us-east-1`). The EventBridge rules are regional, so deploy once per region you want covered
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

The apply publishes a hello event to verify the connection, without touching any real resource. It travels the same connection, API destination, API key and endpoint as a real event, and Prowler Cloud marks the provider as connected once it arrives, without running a scan.

The `prowler_realtime_hello_status` output reports only that EventBridge accepted the event, which is not the same as the endpoint receiving it: delivery is asynchronous. Prowler Cloud is what confirms the connection, and a delivery that fails every retry lands in the dead-letter queue below. The event is published again whenever `prowler_webhook_url` changes.

To re-check the connection at any point, publish it yourself. Use the same region the template deploys to, since the rule only exists on that region's event bus:

```bash
aws events put-events --region us-east-1 --entries '[{
  "Source": "prowler.simulation",
  "DetailType": "test_connection",
  "Detail": "{}"
}]'
```

Failed deliveries are not lost: EventBridge retries for up to 24 hours and then writes the event to the `ProwlerRealtimeDetectionDLQ` queue created in your account, together with the error code and the number of attempts. Responses that are never retried (any 4xx other than 401, 407, 409 and 429) land there on the first attempt. The queue is yours: Prowler has no permission to read it.

> **Note:** the EventBridge rules are regional. They forward only the events delivered to the default event bus of the region set in `region` (`us-east-1` by default). IAM events are global and always land in `us-east-1`, but regional services (EC2 security groups, RDS, per-region Config and GuardDuty) are only covered in the region you deploy to. Run the template once per region you want covered, changing `region` each time.

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
- `prowler_realtime_dlq_url`: URL of the dead-letter queue (null if real-time detection is disabled)
- `prowler_realtime_hello_status`: whether EventBridge accepted the hello event on apply, `Published` or `Failed` with the error

### Handling the API key

Terraform writes every variable it is given to state, including `prowler_api_key`, and marking it `sensitive` only hides it from the CLI output. Before enabling real-time detection:

- Configure an encrypted, access-controlled remote backend (S3 with SSE and a restrictive bucket policy, Terraform Cloud, or equivalent). The default local state is a plaintext file in your working directory.
- Pass the key from your secret manager instead of typing it into a file, for example `export TF_VAR_prowler_api_key="$(your-secret-tool read prowler/api-key)"`.
- Do not commit a populated `terraform.tfvars`, and treat plan files as secrets too.
- Revoking the key in Prowler Cloud stops all ingestion, so rotate it there if a state file is ever exposed.

> **Note:** Terraform will use the AWS credentials of your default profile or AWS_PROFILE environment variable.
