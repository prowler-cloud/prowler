# Configuration File
Several Prowler's checks have user configurable variables that can be modified in a common **configuration file**. This file can be found in the following [path](https://github.com/prowler-cloud/prowler/blob/master/prowler/config/config.yaml):
```
prowler/config/config.yaml
```

Also you can input a custom configuration file using the `--config-file` argument.

## AWS

### Configurable Checks
The following list includes all the AWS checks with configurable variables that can be changed in the configuration yaml file:

| Check Name                                                    | Value                                            | Type            |
|---------------------------------------------------------------|--------------------------------------------------|-----------------|
| `iam_user_accesskey_unused`                                   | `max_unused_access_keys_days`                    | Integer         |
| `iam_user_console_access_unused`                              | `max_console_access_days`                        | Integer         |
| `ec2_elastic_ip_shodan`                                       | `shodan_api_key`                                 | String          |
| `ec2_securitygroup_with_many_ingress_egress_rules`            | `max_security_group_rules`                       | Integer         |
| `ec2_instance_older_than_specific_days`                       | `max_ec2_instance_age_in_days`                   | Integer         |
| `vpc_endpoint_connections_trust_boundaries`                   | `trusted_account_ids`                            | List of Strings |
| `vpc_endpoint_services_allowed_principals_trust_boundaries`   | `trusted_account_ids`                            | List of Strings |
| `cloudwatch_log_group_retention_policy_specific_days_enabled` | `log_group_retention_days`                       | Integer         |
| `appstream_fleet_session_idle_disconnect_timeout`             | `max_idle_disconnect_timeout_in_seconds`         | Integer         |
| `appstream_fleet_session_disconnect_timeout`                  | `max_disconnect_timeout_in_seconds`              | Integer         |
| `appstream_fleet_maximum_session_duration`                    | `max_session_duration_seconds`                   | Integer         |
| `awslambda_function_using_supported_runtimes`                 | `obsolete_lambda_runtimes`                       | Integer         |
| `organizations_scp_check_deny_regions`                        | `organizations_enabled_regions`                  | List of Strings |
| `organizations_delegated_administrators`                      | `organizations_trusted_delegated_administrators` | List of Strings |
| `ecr_repositories_scan_vulnerabilities_in_latest_image`       | `ecr_repository_vulnerability_minimum_severity`  | String          |
| `trustedadvisor_premium_support_plan_subscribed`              | `verify_premium_support_plans`                   | Boolean         |
| `config_recorder_all_regions_enabled`                         | `allowlist_non_default_regions`                  | Boolean         |
| `drs_job_exist`                                               | `allowlist_non_default_regions`                  | Boolean         |
| `guardduty_is_enabled`                                        | `allowlist_non_default_regions`                  | Boolean         |
| `securityhub_enabled`                                         | `allowlist_non_default_regions`                  | Boolean         |
| `rds_instance_backup_enabled`                                  | `check_rds_instance_replicas`      | Boolean        |
| `acm_certificates_expiration_check`                           | `days_to_expire_threshold`                       | Integer         |

## Azure

### Configurable Checks
The following list includes all the Azure checks with configurable variables that can be changed in the configuration yaml file:

| Check Name                                                    | Value                                            | Type            |
|---------------------------------------------------------------|--------------------------------------------------|-----------------|
| `network_public_ip_shodan`                                   | `shodan_api_key`                    | String         |
| `app_ensure_php_version_is_latest`                            | `php_latest_version`                             | String          |
| `app_ensure_python_version_is_latest`                         | `python_latest_version`                          | String          |
| `app_ensure_java_version_is_latest`                           | `java_latest_version`                            | String          |


## GCP

### Configurable Checks

## Config YAML File Structure

???+ note
    This is the new Prowler configuration file format. The old one without provider keys is still compatible just for the AWS provider.

```yaml title="config.yaml"
# AWS Configuration
aws:
  # AWS Global Configuration
  # aws.allowlist_non_default_regions --> Allowlist Failed Findings in non-default regions for GuardDuty, SecurityHub, DRS and Config
  allowlist_non_default_regions: False

  # AWS IAM Configuration
  # aws.iam_user_accesskey_unused --> CIS recommends 45 days
  max_unused_access_keys_days: 45
  # aws.iam_user_console_access_unused --> CIS recommends 45 days
  max_console_access_days: 45

  # AWS EC2 Configuration
  # aws.ec2_elastic_ip_shodan
  # TODO: create common config
  shodan_api_key: null
  # aws.ec2_securitygroup_with_many_ingress_egress_rules --> by default is 50 rules
  max_security_group_rules: 50
  # aws.ec2_instance_older_than_specific_days --> by default is 6 months (180 days)
  max_ec2_instance_age_in_days: 180

  # AWS VPC Configuration (vpc_endpoint_connections_trust_boundaries, vpc_endpoint_services_allowed_principals_trust_boundaries)
  # AWS SSM Configuration (aws.ssm_documents_set_as_public)
  # Single account environment: No action required. The AWS account number will be automatically added by the checks.
  # Multi account environment: Any additional trusted account number should be added as a space separated list, e.g.
  # trusted_account_ids : ["123456789012", "098765432109", "678901234567"]
  trusted_account_ids: []

  # AWS Cloudwatch Configuration
  # aws.cloudwatch_log_group_retention_policy_specific_days_enabled --> by default is 365 days
  log_group_retention_days: 365

  # AWS AppStream Session Configuration
  # aws.appstream_fleet_session_idle_disconnect_timeout
  max_idle_disconnect_timeout_in_seconds: 600 # 10 Minutes
  # aws.appstream_fleet_session_disconnect_timeout
  max_disconnect_timeout_in_seconds: 300 # 5 Minutes
  # aws.appstream_fleet_maximum_session_duration
  max_session_duration_seconds: 36000 # 10 Hours

  # AWS Lambda Configuration
  # aws.awslambda_function_using_supported_runtimes
  obsolete_lambda_runtimes:
    [
      "java8",
      "go1.x",
      "provided",
      "python3.6",
      "python2.7",
      "python3.7",
      "nodejs4.3",
      "nodejs4.3-edge",
      "nodejs6.10",
      "nodejs",
      "nodejs8.10",
      "nodejs10.x",
      "nodejs12.x",
      "nodejs14.x",
      "dotnet5.0",
      "dotnetcore1.0",
      "dotnetcore2.0",
      "dotnetcore2.1",
      "dotnetcore3.1",
      "ruby2.5",
      "ruby2.7",
    ]

  # AWS Organizations
  # aws.organizations_scp_check_deny_regions
  # aws.organizations_enabled_regions: [
  #   "eu-central-1",
  #   "eu-west-1",
  #   "us-east-1"
  # ]
  organizations_enabled_regions: []
  organizations_trusted_delegated_administrators: []

  # AWS ECR
  # aws.ecr_repositories_scan_vulnerabilities_in_latest_image
  # CRITICAL
  # HIGH
  # MEDIUM
  ecr_repository_vulnerability_minimum_severity: "MEDIUM"

  # AWS Trusted Advisor
  # aws.trustedadvisor_premium_support_plan_subscribed
  verify_premium_support_plans: True

  # AWS RDS
  # aws.rds_instance_backup_enabled
  # Whether to check RDS instance replicas or not
  check_rds_instance_replicas: False

  # AWS ACM Configuration
  # aws.acm_certificates_expiration_check
  days_to_expire_threshold: 7

# Azure Configuration
azure:
  # Azure Network Configuration
  # azure.network_public_ip_shodan
  # TODO: create common config
  shodan_api_key: null

  # Azure App Service
  # azure.app_ensure_php_version_is_latest
  php_latest_version: "8.2"
  # azure.app_ensure_python_version_is_latest
  python_latest_version: "3.12"
  # azure.app_ensure_java_version_is_latest
  java_latest_version: "17"

# GCP Configuration
gcp:
  # GCP Compute Configuration
  # gcp.compute_public_address_shodan
  shodan_api_key: null

```
