# Custom Checks Metadata

In certain organizations, the severity of specific checks might differ from the default values defined in the check's metadata. For instance, while `s3_bucket_level_public_access_block` could be deemed `critical` for some organizations, others might assign a different severity level.

The custom metadata option offers a means to override default metadata set by Prowler

You can utilize `--custom-checks-metadata-file` followed by the path to your custom checks metadata YAML file.

## Available Fields

The list of supported check's metadata fields that can be override are listed as follows:

- Severity
- CheckTitle
- Risk
- RelatedUrl
- Remediation
  - Code
    - CLI
    - NativeIaC
    - Other
    - Terraform
  - Recommendation
    - Text
    - Url

## File Syntax

This feature is available for all the providers supported in Prowler since the metadata format is common between all the providers. The following is the YAML format for the custom checks metadata file:
```yaml title="custom_checks_metadata.yaml"
CustomChecksMetadata:
  aws:
    Checks:
      s3_bucket_level_public_access_block:
        Severity: high
        CheckTitle: S3 Bucket Level Public Access Block
        Description: This check ensures that the S3 bucket level public access block is enabled.
        Risk: This check is important because it ensures that the S3 bucket level public access block is enabled.
        RelatedUrl: https://docs.aws.amazon.com/AmazonS3/latest/dev/access-control-block-public-access.html
        Remediation:
          Code:
            CLI: aws s3api put-public-access-block --bucket <bucket-name> --public-access-block-configuration BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true
            NativeIaC: https://aws.amazon.com/es/s3/features/block-public-access/
            Other: https://docs.aws.amazon.com/AmazonS3/latest/userguide/access-control-block-public-access.html
            Terraform: https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/s3_bucket_public_access_block
          Recommendation:
            Text: Enable the S3 bucket level public access block.
            Url: https://docs.aws.amazon.com/AmazonS3/latest/dev/access-control-block-public-access.html
      s3_bucket_no_mfa_delete:
        Severity: high
        CheckTitle: S3 Bucket No MFA Delete
        Description: This check ensures that the S3 bucket does not allow delete operations without MFA.
        Risk: This check is important because it ensures that the S3 bucket does not allow delete operations without MFA.
        RelatedUrl: https://docs.aws.amazon.com/AmazonS3/latest/dev/Versioning.html
        Remediation:
          Code:
            CLI: aws s3api put-bucket-versioning --bucket <bucket-name> --versioning-configuration Status=Enabled
            NativeIaC: https://aws.amazon.com/es/s3/features/versioning/
            Other: https://docs.aws.amazon.com/AmazonS3/latest/dev/Versioning.html
            Terraform: https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/s3_bucket_versioning
          Recommendation:
            Text: Enable versioning on the S3 bucket.
            Url: https://docs.aws.amazon.com/AmazonS3/latest/dev/Versioning.html
  azure:
    Checks:
      storage_infrastructure_encryption_is_enabled:
        Severity: medium
        CheckTitle: Storage Infrastructure Encryption Is Enabled
        Description: This check ensures that storage infrastructure encryption is enabled.
        Risk: This check is important because it ensures that storage infrastructure encryption is enabled.
        RelatedUrl: https://docs.microsoft.com/en-us/azure/storage/common/storage-service-encryption
        Remediation:
          Code:
            CLI: az storage account update --name <storage-account-name> --resource-group <resource-group-name> --set properties.encryption.services.blob.enabled=true properties.encryption.services.file.enabled=true properties.encryption.services.queue.enabled=true properties.encryption.services.table.enabled=true
            NativeIaC: https://docs.microsoft.com/en-us/azure/templates/microsoft.storage/storageaccounts
            Other: https://docs.microsoft.com/en-us/azure/storage/common/storage-service-encryption
            Terraform: https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/storage_account
          Recommendation:
            Text: Enable storage infrastructure encryption.
            Url: https://docs.microsoft.com/en-us/azure/storage/common/storage-service-encryption
  gcp:
    Checks:
      compute_instance_public_ip:
        Severity: critical
        CheckTitle: Compute Instance Public IP
        Description: This check ensures that the compute instance does not have a public IP.
        Risk: This check is important because it ensures that the compute instance does not have a public IP.
        RelatedUrl: https://cloud.google.com/compute/docs/ip-addresses/reserve-static-external-ip-address
        Remediation:
          Code:
            CLI: https://docs.prowler.com/checks/gcp/google-cloud-public-policies/bc_gcp_public_2#cli-command
            NativeIaC: https://cloud.google.com/compute/docs/reference/rest/v1/instances
            Other: https://cloud.google.com/compute/docs/ip-addresses/reserve-static-external-ip-address
            Terraform: https://registry.terraform.io/providers/hashicorp/google/latest/docs/resources/compute_instance
          Recommendation:
            Text: Remove the public IP from the compute instance.
            Url: https://cloud.google.com/compute/docs/ip-addresses/reserve-static-external-ip-address
  kubernetes:
    Checks:
      apiserver_anonymous_requests:
        Severity: low
        CheckTitle: APIServer Anonymous Requests
        Description: This check ensures that anonymous requests to the APIServer are disabled.
        Risk: This check is important because it ensures that anonymous requests to the APIServer are disabled.
        RelatedUrl: https://kubernetes.io/docs/reference/access-authn-authz/authentication/
        Remediation:
          Code:
            CLI: --anonymous-auth=false
            NativeIaC: https://docs.prowler.com/checks/kubernetes/kubernetes-policy-index/ensure-that-the-anonymous-auth-argument-is-set-to-false-1#kubernetes
            Other: https://kubernetes.io/docs/reference/access-authn-authz/authentication/
            Terraform: https://registry.terraform.io/providers/hashicorp/kubernetes/latest/docs/resources/cluster_role_binding
          Recommendation:
            Text: Disable anonymous requests to the APIServer.
            Url: https://kubernetes.io/docs/reference/access-authn-authz/authentication/
```

## Usage

Executing the following command will assess all checks and generate a report while overriding the metadata for those checks:
```sh
prowler <provider> --custom-checks-metadata-file <path/to/custom/metadata>
```

This customization feature enables organizations to tailor the severity of specific checks based on their unique requirements, providing greater flexibility in security assessment and reporting.
