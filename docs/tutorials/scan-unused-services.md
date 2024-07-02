# Scan Unused Services

???+ note
    Currently only available on the AWS provider.

By default, Prowler only scans the cloud services that are used (where resources are created) to reduce the number of findings in Prowler's reports. If you want Prowler to also scan unused services, you can use the following command:

```console
prowler <provider> --scan-unused-services
```

## Services that are ignored
### AWS
#### ACM
You can have certificates in ACM that are not in use by any AWS resource.
Prowler will check if every certificate is going to expire soon, if this certificate is not in use by default it is not going to be check if it is expired, is going to expire soon or it is good.

- `acm_certificates_expiration_check`

#### Athena
When you create an AWS Account, Athena will create a default primary workgroup for you.
Prowler will check if that workgroup is enabled and if it is being used by checking if there were queries in the last 45 days.
If not, the findings of the following checks will not appear:

  - `athena_workgroup_encryption`
  - `athena_workgroup_enforce_configuration`

#### CloudTrail
AWS CloudTrail should have at least one trail with a data event to record all S3 object-level API operations, Prowler will check first if there are S3 buckets in your account before alerting this issue.

  - `cloudtrail_s3_dataevents_read_enabled`
  - `cloudtrail_s3_dataevents_write_enabled`

#### EC2
If EBS default encyption is not enabled, sensitive information at rest is not protected in EC2. But Prowler will only create a finding if there are EBS Volumes where this default configuration could be enforced by default.

  - `ec2_ebs_default_encryption`

If your Security groups are not properly configured the attack surface is increased, nonetheless, Prowler will detect those security groups that are being used (they are attached) to only notify those that are being used. This logic applies to the 15 checks related to open ports in security groups and the check for the default security group.

  - `ec2_securitygroup_allow_ingress_from_internet_to_port_X` (15 checks)
  - `ec2_securitygroup_default_restrict_traffic`

Prowler will also check for used Network ACLs to only alerts those with open ports that are being used.

  - `ec2_networkacl_allow_ingress_X_port` (3 checks)


#### Glue
It is a best practice to encrypt both metadata and connection passwords in AWS Glue Data Catalogs, however, Prowler will detect if the service is in use by checking if there are any Data Catalog tables.

  - `glue_data_catalogs_connection_passwords_encryption_enabled`
  - `glue_data_catalogs_metadata_encryption_enabled`

#### Inspector
Amazon Inspector is a vulnerability discovery service that automates continuous scanning for security vulnerabilities within your Amazon EC2, Amazon ECR, and AWS Lambda environments. Prowler recommends to enable it and resolve all the Inspector's findings. Ignoring the unused services, Prowler will only notify you if there are any Lambda functions, EC2 instances or ECR repositories in the region where Amazon inspector should be enabled.

  - `inspector2_is_enabled`

#### Macie
Amazon Macie is a security service that uses machine learning to automatically discover, classify and protect sensitive data in S3 buckets. Prowler will only create a finding when Macie is not enabled if there are S3 buckets in your account.

  - `macie_is_enabled`

#### Network Firewall
Without a network firewall, it can be difficult to monitor and control traffic within the VPC. However, Prowler will only alert you for those VPCs that are in use, in other words, only the VPCs where you have ENIs (network interfaces).

  - `networkfirewall_in_all_vpc`

#### S3
You should enable Public Access Block at the account level to prevent the exposure of your data stored in S3. Prowler though will only check this block configuration if you have S3 buckets in your AWS account.

  - `s3_account_level_public_access_blocks`

#### VPC
VPC Flow Logs provide visibility into network traffic that traverses the VPC and can be used to detect anomalous traffic or insight during security workflows. Nevertheless, Prowler will only check if the Flow Logs are enabled for those VPCs that are in use, in other words, only the VPCs where you have ENIs (network interfaces).

  - `vpc_flow_logs_enabled`

VPC subnets must not have public IP addresses by default to prevent the exposure of your resources to the internet. Prowler will only check this configuration for those VPCs that are in use, in other words, only the VPCs where you have ENIs (network interfaces).

  - `vpc_subnet_no_public_ip_by_default`

VPCs should have separate private and public subnets to prevent the exposure of your resources to the internet. Prowler will only check this configuration for those VPCs that are in use, in other words, only the VPCs where you have ENIs (network interfaces).

  - `vpc_subnet_separate_private_public`

VPCs should have subnets in different availability zones to prevent a single point of failure. Prowler will only check this configuration for those VPCs that are in use, in other words, only the VPCs where you have ENIs (network interfaces).

  - `vpc_subnet_different_az`
