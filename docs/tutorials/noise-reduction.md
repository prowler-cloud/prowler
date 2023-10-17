# Noise Reduction

> Currently only available on the AWS provider.

Prowler allows you to ignore noisy findings in services that are not used (do not have resources) so you can reduce noise in Prowler's reports.

```console
prowler <provider> --ignore-unused-services
```

## Checks with noise reduction
### AWS
  - accessanalyzer_enabled_without_findings
  - athena_workgroup_encryption
  - athena_workgroup_enforce_configuration
  - backup_plans_exist
  - cloudtrail_s3_dataevents_read_enabled
  - cloudtrail_s3_dataevents_write_enabled
  - ec2_ebs_default_encryption
  - ec2_networkacl_allow_ingress_X_port
  - ec2_securitygroup_allow_ingress_from_internet_to_port_X
  - glue_data_catalogs_connection_passwords_encryption_enabled
  - glue_data_catalogs_metadata_encryption_enabled
  - inspector2_findings_exist
  - macie_is_enabled
  - networkfirewall_in_all_vpc
  - resourceexplorer2_indexes_found
  - s3_account_level_public_access_blocks
  - vpc_flow_logs_enabled
