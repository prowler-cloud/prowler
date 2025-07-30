# Mute Findings (Mutelist)

Prowler App allows users to mute specific findings to focus on the most critical security issues. This comprehensive guide demonstrates how to effectively use the Mutelist feature to manage and prioritize security findings.

## What Is the Mutelist Feature?

The Mutelist feature enables users to:

- **Suppress specific findings** from appearing in future scans
- **Focus on critical issues** by hiding resolved or accepted risks
- **Maintain audit trails** of muted findings for compliance purposes
- **Streamline security workflows** by reducing noise from non-critical findings

## Prerequisites

Before muting findings, ensure:

- Valid access to Prowler App with appropriate permissions
- A provider added to the Prowler App
- Understanding of the security implications of muting specific findings

???+ warning
    Muting findings does not resolve underlying security issues. Review each finding carefully before muting to ensure it represents an acceptable risk or has been properly addressed.

## Step 1: Add a provider

To configure Mutelist:

1. Log into Prowler App
2. Navigate to the providers page
![Add provider](../img/mutelist-ui-1.png)
3. Add a provider, then "Configure Muted Findings" button will be enabled in providers page and scans page
![Button enabled in providers page](../img/mutelist-ui-2.png)
![Button enabled in scans pages](../img/mutelist-ui-3.png)


## Step 2: Configure Mutelist

1. Open the modal by clicking "Configure Muted Findings" button
![Open modal](../img/mutelist-ui-4.png)
1. Provide a valid Mutelist in `YAML` format. More details about Mutelist [here](../tutorials/mutelist.md)
![Valid YAML configuration](../img/mutelist-ui-5.png)
If the YAML configuration is invalid, an error message will be displayed
![Wrong YAML configuration](../img/mutelist-ui-7.png)
![Wrong YAML configuration 2](../img/mutelist-ui-8.png)

## Step 3: Review the Mutelist

1. Once added, the configuration can be removed or updated
![Remove or update configuration](../img/mutelist-ui-6.png)

## Step 4: Check muted findings in the scan results

1. Run a new scan
2. Check the muted findings in the scan results
![Check muted fidings](../img/mutelist-ui-9.png)

???+ note
    The Mutelist configuration takes effect on the next scans.

## Mutelist Ready To Use Examples

Below are examples for different cloud providers supported by Prowler App. Check how the mutelist works [here](https://docs.prowler.com/projects/prowler-open-source/en/latest/tutorials/mutelist/#how-the-mutelist-works).

### AWS Provider

#### Basic AWS Mutelist
```yaml
Mutelist:
  Accounts:
    "123456789012":
      Checks:
        "iam_user_hardware_mfa_enabled":
          Regions:
            - "us-east-1"
          Resources:
            - "user-1"
            - "user-2"
          Description: "Mute MFA findings for specific users in us-east-1"
        "s3_bucket_public_access":
          Regions:
            - "*"
          Resources:
            - "public-website-bucket"
          Description: "Mute public access findings for website bucket"
```

#### AWS Service-Wide Muting
```yaml
Mutelist:
  Accounts:
    "*":
      Checks:
        "ec2_*":
          Regions:
            - "*"
          Resources:
            - "*"
          Description: "Mute all EC2-related findings across all accounts and regions"
```

#### AWS Tag-Based Muting
```yaml
Mutelist:
  Accounts:
    "*":
      Checks:
        "*":
          Regions:
            - "*"
          Resources:
            - "*"
          Tags:
            - "environment=dev"
            - "project=test"
          Description: "Mute all findings for resources tagged with environment=dev or project=test"
```

### Azure Provider

???+ note
    For Azure provider, the Account ID is the Subscription Name and the Region is the Location.

#### Basic Azure Mutelist
```yaml
Mutelist:
  Accounts:
    "MySubscription":
      Checks:
        "storage_blob_public_access_level_is_disabled":
          Regions:
            - "East US"
            - "West US"
          Resources:
            - "publicstorageblob"
          Description: "Mute public access findings for specific blob storage resource"
        "app_function_vnet_integration_enabled":
          Regions:
            - "*"
          Resources:
            - "app-vnet-peering-*"
          Description: "Mute App Function Vnet findings related with the reources pattern"
```

#### Azure Resource Group Muting
```yaml
Mutelist:
  Accounts:
    "*":
      Checks:
        "*":
          Regions:
            - "*"
          Resources:
            - "rg-dev-*"
            - "rg-test-*"
          Tags:
            - "environment=development"
          Description: "Mute all findings for development resource groups"
```

### GCP Provider

???+ note
    For GCP provider, the Account ID is the Project ID and the Region is the Zone.

#### Basic GCP Mutelist
```yaml
Mutelist:
  Accounts:
    "my-gcp-project":
      Checks:
        "cloudstorage_bucket_public_access":
          Regions:
            - "us-central1"
            - "us-east1"
          Resources:
            - "public-bucket-*"
          Description: "Mute public access findings for specific bucket pattern"
        "compute_instance_public_ip":
          Regions:
            - "*"
          Resources:
            - "public-instance"
          Description: "Mute public access findings for specific compute instance"
```

#### GCP Project-Wide Muting
```yaml
Mutelist:
  Accounts:
    "*":
      Checks:
        "*":
          Regions:
            - "*"
          Resources:
            - "*"
          Tags:
            - "environment=staging"
          Description: "Mute all GCP findings for staging environment"
```
### Kubernetes Provider

???+ note
    For Kubernetes provider, the Account ID is the Cluster Name and the Region is the Namespace.

#### Basic Kubernetes Mutelist
```yaml
Mutelist:
  Accounts:
    "my-cluster":
      Checks:
        "etcd_client_cert_auth":
          Regions:
            - "default"
            - "kube-system"
          Resources:
            - "system-pod-*"
          Description: "Mute etcd cert authorization findings for the matching resources"
        "kubelet_tls_cert_and_key":
          Regions:
            - "*"
          Resources:
            - "*"
          Description: "Mute kubelet tls findings across all namespaces"
```

#### Kubernetes Namespace Muting
```yaml
Mutelist:
  Accounts:
    "*":
      Checks:
        "*":
          Regions:
            - "monitoring"
            - "logging"
          Resources:
            - "*"
          Description: "Mute all findings for monitoring and logging namespaces"
```

### Microsoft 365 Provider

#### Basic Microsoft 365 Mutelist
```yaml
Mutelist:
  Accounts:
    "my-tenant.onmicrosoft.com":
      Checks:
        "entra_admin_portals_access_restriction":
          Regions:
            - "*"
          Resources:
            - "test-user"
          Description: "Mute findings related with administrative roles access for test-user"
        "sharepoint_external_sharing_managed":
          Regions:
            - "*"
          Resources:
            - "public-site-*"
          Description: "Mute external sharing findings for public sites"
```

#### Microsoft 365 Tenant-Wide Muting
```yaml
Mutelist:
  Accounts:
    "*":
      Checks:
        "*":
          Regions:
            - "*"
          Resources:
            - "*"
          Tags:
            - "department=IT"
          Description: "Mute all M365 findings for IT department resources"
```

### Multi-Cloud Mutelist

You can combine multiple providers in a single mutelist configuration:

```yaml
Mutelist:
  Accounts:
    # AWS Account
    "123456789012":
      Checks:
        "s3_bucket_public_access":
          Regions:
            - "us-east-1"
          Resources:
            - "public-website"
          Description: "Mute public access findings for AWS website bucket"

    # Azure Subscription
    "MyAzureSubscription":
      Checks:
        "storage_blob_public_access_level_is_disabled":
          Regions:
            - "East US"
          Resources:
            - "public-storage"
          Description: "Mute public access findings for Azure storage account"

    # GCP Project
    "my-gcp-project":
      Checks:
        "cloudstorage_bucket_public_access":
          Regions:
            - "us-central1"
          Resources:
            - "public-bucket"
          Description: "Mute public access findings for GCP storage bucket"

    # Kubernetes Cluster
    "my-k8s-cluster":
      Checks:
        "kubelet_tls_cert_and_key":
          Regions:
            - "default"
          Resources:
            - "kubelet-test"
          Description: "Mute kubelet tls findings related with kubelet-test"

    # Microsoft 365 Tenant
    "my-tenant.onmicrosoft.com":
      Checks:
        "sharepoint_external_sharing_managed":
          Regions:
            - "*"
          Resources:
            - "public-site"
          Description: "Mute external sharing findings for public SharePoint site"
```

### Advanced Mutelist Features

#### Using Regular Expressions
```yaml
Mutelist:
  Accounts:
    "*":
      Checks:
        "*":
          Regions:
            - "*"
          Resources:
            - ".*-test-.*"        # Matches any resource containing "-test-"
            - "dev-.*"            # Matches resources starting with "dev-"
            - ".*-prod$"          # Matches resources ending with "-prod"
          Description: "Mute findings for test and development resources using regex"
```

#### Using Exceptions
```yaml
Mutelist:
  Accounts:
    "*":
      Checks:
        "*":
          Regions:
            - "*"
          Resources:
            - "*"
          Exceptions:
            Accounts:
              - "987654321098"
            Regions:
              - "us-west-2"
            Resources:
              - "critical-resource"
            Tags:
              - "environment=production"
          Description: "Mute all findings except for critical production resources"
```

#### Tag-Based Logic
```yaml
Mutelist:
  Accounts:
    "*":
      Checks:
        "*":
          Regions:
            - "*"
          Resources:
            - "*"
          Tags:
            - "environment=dev | environment=test"    # OR logic
            - "project=alpha"                      # AND logic
          Description: "Mute findings for dev/test environments in alpha project"
```

### Best Practices

1. **Start Small**: Begin with specific resources and gradually expand
2. **Document Reasons**: Always include descriptions for audit trails
3. **Regular Reviews**: Periodically review muted findings
4. **Use Tags**: Leverage resource tags for better organization
5. **Test Changes**: Validate mutelist changes in non-production environments
6. **Monitor Impact**: Track how muting affects your security posture

### Validation

Prowler App validates your mutelist configuration and will display errors for:

- Invalid YAML syntax
- Missing required fields
- Invalid regular expressions
- Unsupported provider-specific configurations
