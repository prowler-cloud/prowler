## Deployment using Terraform

To deploy the Prowler Scan Role in order to allow scanning your AWS account from Prowler, please run the following commands in your terminal:

1. `terraform init`
2. `terraform plan`
3. `terraform apply`

During the `terraform plan` and `terraform apply` steps you will be asked for an External ID to be configured in the `ProwlerScan` IAM role.

### Variables

- `external_id` (required): External ID for role assumption security
- `account_id` (optional): AWS Account ID that will assume the role (defaults to Prowler Cloud: "232136659152")
- `iam_principal` (optional): IAM principal pattern allowed to assume the role (defaults to Prowler Cloud: "role/prowler*")
- `enable_s3_integration` (optional): Enable S3 integration for storing scan reports (default: false)
- `s3_integration_bucket_name` (conditional): S3 bucket name for reports (required if `enable_s3_integration` is true)
- `s3_integration_bucket_account` (conditional): S3 bucket owner account ID (required if `enable_s3_integration` is true)

### Usage Examples

#### Basic deployment (without S3 integration):
```bash
terraform apply -var="external_id=your-external-id-here"
```

#### With S3 integration enabled:
```bash
terraform apply \
  -var="external_id=your-external-id-here" \
  -var="enable_s3_integration=true" \
  -var="s3_integration_bucket_name=your-s3-bucket-name" \
  -var="s3_integration_bucket_account=123456789012"
```

#### Using terraform.tfvars file:
Create a `terraform.tfvars` file:
```hcl
external_id                   = "your-external-id-here"
enable_s3_integration         = true
s3_integration_bucket_name    = "your-s3-bucket-name"
s3_integration_bucket_account = "123456789012"
```

Then run: `terraform apply`

> Note that Terraform will use the AWS credentials of your default profile.
