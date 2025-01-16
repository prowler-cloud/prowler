## Deployment using Terraform

To deploy the Prowler Scan Role in order to allow to scan you AWS account from Prowler, please run the following commands in your terminal:
1. `terraform init`
2. `terraform plan`
3. `terraform apply`

During the `terraform plan` and `terraform apply` steps you will be asked for an External ID to be configured in the `ProwlerScan` IAM role.

> Note that Terraform will use the AWS credentials of your default profile.
