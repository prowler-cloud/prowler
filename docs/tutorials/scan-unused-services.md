# Scanning Unused Services

???+ note
    This feature is currently available only for the AWS provider.

By default, Prowler scans only actively used cloud services (services with resources deployed). This reduces unnecessary findings in reports. To include unused services in the scan, use the following command:

```console
prowler <provider> --scan-unused-services
```

## Services Ignored

### AWS

#### ACM (AWS Certificate Manager)

Certificates stored in ACM without active usage in AWS resources are excluded. By default, Prowler only scans actively used certificates. Unused certificates will not be checked if they are expired, if their expiring date is near or if they are good.

- `acm_certificates_expiration_check`

#### Athena

Upon AWS account creation, Athena provisions a default primary workgroup for the user. Prowler verifies if this workgroup is enabled and used by checking for queries within the last 45 days. If Athena is unused, findings related to its checks will not appear.

- `athena_workgroup_encryption`
- `athena_workgroup_enforce_configuration`

#### AWS CloudTrail

AWS CloudTrail should have at least one trail with a data event to record all S3 object-level API operations. Before flagging this issue, Prowler verifies if S3 buckets exist in the account.

- `cloudtrail_s3_dataevents_read_enabled`
- `cloudtrail_s3_dataevents_write_enabled`

#### AWS Elastic Compute Cloud (EC2)

If Amazon Elastic Block Store (EBS) default encyption is not enabled, sensitive data at rest will remain unprotected in EC2. However, Prowler will only generate a finding if EBS volumes exist where default encryption could be enforced.

- `ec2_ebs_default_encryption`

**Security Groups**: Misconfigured security groups increase the attack surface.

Prowler scans only attached security groups to report vulnerabilities in actively used configurations. Applies to:

- 15 security group-related checks, including open ports and ingress/egress traffic rules.

    - `ec2_securitygroup_allow_ingress_from_internet_to_port_X`
    - `ec2_securitygroup_default_restrict_traffic`
    - `ec2_securitygroup_allow_wide_open_public_ipv4`

- 3 network ACL-related checks, ensuring only active ACLs with open ports are flagged.

    - `ec2_networkacl_allow_ingress_X_port`

#### AWS Glue

AWS Glue best practices recommend encrypting metadata and connection passwords in Data Catalogs.

Prowler verifies service usage by checking for existing Data Catalog tables before applying findings.

- `glue_data_catalogs_connection_passwords_encryption_enabled`
- `glue_data_catalogs_metadata_encryption_enabled`

#### Amazon Inspector

Amazon Inspector is a vulnerability discovery service that automates continuous security scans for Amazon EC2, Amazon ECR, and AWS Lambda environments. Prowler recommends enabling Amazon Inspector and addressing all findings. By default, Prowler only triggers alerts if there are Lambda functions, EC2 instances, or ECR repositories in the region where Amazon Inspector should be enabled.

- `inspector2_is_enabled`

#### Amazon Macie

Amazon Macie leverages machine learning to automatically discover, classify, and protect sensitive data in S3 buckets. Prowler only generates findings if Macie is disabled and there are S3 buckets in the AWS account.

- `macie_is_enabled`

#### Network Firewall

A network firewall is essential for monitoring and controlling traffic within a Virtual Private Cloud (VPC). Prowler only alerts for VPCs in use, specifically those containing ENIs (Elastic Network Interfaces).

- `networkfirewall_in_all_vpc`

#### Amazon S3

To prevent unintended data exposure:

Public Access Block should be enabled at the account level. Prowler only checks this setting if S3 buckets exist in the account.

- `s3_account_level_public_access_blocks`

#### Virtual Private Cloud (VPC)

VPC settings directly impact network security and availability.

- VPC Flow Logs: Provide visibility into network traffic for security monitoring. Prowler only checks if Flow Logs are enabled for VPCs in use, i.e., those with active ENIs.

    - `vpc_flow_logs_enabled`

- VPC Subnet Public IP Restrictions: Prevent unintended exposure of resources to the internet. Prowler only checks this configuration for VPCs in use, i.e., those with active ENIs.

    - `vpc_subnet_no_public_ip_by_default`

- Separate Private and Public Subnets: Best practice to avoid exposure risks. Prowler only checks this configuration for VPCs in use, i.e., those with active ENIs.

    - `vpc_subnet_separate_private_public`

- Multi-AZ Subnet Distribution: VPCs should have subnets in different availability zones to prevent a single point of failure. Prowler only checks this configuration for VPCs in use, i.e., those with active ENIs.

    - `vpc_subnet_different_az`
