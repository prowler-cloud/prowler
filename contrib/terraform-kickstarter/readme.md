# Install Security Baseline Kickstarter with Prowler

## Introduction

The following demonstrates how to quickly install the resources necessary to perform a security baseline using Prowler.  The speed is based on the prebuilt terraform module that can configure all the resources necessary to run Prowler with the findings being sent to AWS Security Hub.

## Install

Installing Prowler with Terraform is simple and can be completed in under 1 minute.

- Start AWS CloudShell
- Run the following commands to install Terraform and clone the Prowler git repo
  ```
  git clone https://github.com/prowler-cloud/prowler.git
  cd prowler
  sudo yum install -y yum-utils
  sudo yum-config-manager --add-repo https://rpm.releases.hashicorp.com/AmazonLinux/hashicorp.repo
  sudo yum -y install terraform
  cd util/terraform-kickstarter
  ```
- Issue a `terraform init`

- Issue a `terraform apply`

  ![Prowler Install](https://prowler-docs.s3.amazonaws.com/Prowler-Terraform-Install.gif)

   - It is likely an error will return related to the SecurityHub subscription.  This appears to be Terraform related and you can validate the configuration by navigating to the SecurityHub console.  Click Integrations and search for Prowler. Take note of the green check where it says *Accepting findings*

  ![Prowler Subscription](https://prowler-docs.s3.amazonaws.com/Validate-Prowler-Subscription.gif)


Thats it!  Install is now complete.  The resources include a Cloudwatch event that will trigger the AWS Codebuild to run daily at 00:00 GMT.  If you'd like to run an assessment after the deployment then simply navigate to the Codebuild console and start the job manually.

## Terraform Resources

## Requirements

| Name | Version |
|------|---------|
| <a name="requirement_aws"></a> [aws](#requirement\_aws) | ~> 3.54 |

## Providers

| Name | Version |
|------|---------|
| <a name="provider_aws"></a> [aws](#provider\_aws) | 3.56.0 |

## Modules

No modules.

## Resources

| Name | Type |
|------|------|
| [aws_cloudwatch_event_rule.prowler_check_scheduler_event](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/cloudwatch_event_rule) | resource |
| [aws_cloudwatch_event_target.run_prowler_scan](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/cloudwatch_event_target) | resource |
| [aws_codebuild_project.prowler_codebuild](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/codebuild_project) | resource |
| [aws_iam_policy.prowler_event_trigger_policy](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/iam_policy) | resource |
| [aws_iam_policy.prowler_kickstarter_iam_policy](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/iam_policy) | resource |
| [aws_iam_policy_attachment.prowler_event_trigger_policy_attach](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/iam_policy_attachment) | resource |
| [aws_iam_policy_attachment.prowler_kickstarter_iam_policy_attach](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/iam_policy_attachment) | resource |
| [aws_iam_role.prowler_event_trigger_role](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/iam_role) | resource |
| [aws_iam_role.prowler_kick_start_role](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/iam_role) | resource |
| [aws_s3_bucket.prowler_report_storage_bucket](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/s3_bucket) | resource |
| [aws_s3_bucket_policy.prowler_report_storage_bucket_policy](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/s3_bucket_policy) | resource |
| [aws_s3_bucket_public_access_block.prowler_report_storage_bucket_block_public](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/s3_bucket_public_access_block) | resource |
| [aws_securityhub_account.securityhub_resource](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/securityhub_account) | resource |
| [aws_securityhub_product_subscription.security_hub_enable_prowler_findings](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/securityhub_product_subscription) | resource |
| [aws_caller_identity.current](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/data-sources/caller_identity) | data source |
| [aws_iam_policy.SecurityAudit](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/data-sources/iam_policy) | data source |
| [aws_region.current](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/data-sources/region) | data source |

## Inputs

| Name | Description | Type | Default | Required |
|------|-------------|------|---------|:--------:|
| <a name="input_codebuild_timeout"></a> [codebuild\_timeout](#input\_codebuild\_timeout) | Codebuild timeout setting | `number` | `300` | no |
| <a name="input_enable_security_hub"></a> [enable\_security\_hub](#input\_enable\_security\_hub) | Enable AWS SecurityHub. | `bool` | `true` | no |
| <a name="input_enable_security_hub_prowler_subscription"></a> [enable\_security\_hub\_prowler\_subscription](#input\_enable\_security\_hub\_prowler\_subscription) | Enable a Prowler Subscription. | `bool` | `true` | no |
| <a name="input_prowler_cli_options"></a> [prowler\_cli\_options](#input\_prowler\_cli\_options) | Run Prowler With The Following Command | `string` | `"-q -M json-asff -S -f us-east-1"` | no |
| <a name="input_prowler_schedule"></a> [prowler\_schedule](#input\_prowler\_schedule) | Run Prowler based on cron schedule | `string` | `"cron(0 0 ? * * *)"` | no |
| <a name="input_select_region"></a> [select\_region](#input\_select\_region) | Uses the following AWS Region. | `string` | `"us-east-1"` | no |

## Outputs

| Name | Description |
|------|-------------|
| <a name="output_account_id"></a> [account\_id](#output\_account\_id) | n/a |

## Kickoff Prowler Assessment From Install to Assessment Demo (Link to YouTube)

  [![Prowler Install](https://img.youtube.com/vi/ShhzIArO8X0/0.jpg)](https://www.youtube.com/watch?v=ShhzIArO8X0 "Prowler Install")
