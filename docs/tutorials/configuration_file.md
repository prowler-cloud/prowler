# Configuration File
Several Prowler's checks have user configurable variables that can be modified in a common **configuration file**. This file can be found in the following [path](https://github.com/prowler-cloud/prowler/blob/master/prowler/config/config.yaml):
```
prowler/config/config.yaml
```

Also you can input a custom configuration file using the `--config-file` argument.

## AWS

### Configurable Checks
The following list includes all the AWS checks with configurable variables that can be changed in the configuration yaml file:

| Check Name  | Value  | Type  |
|---|---|---|
| `ec2_elastic_ip_shodan`  | `shodan_api_key`  | String |
| `ec2_securitygroup_with_many_ingress_egress_rules`  | `max_security_group_rules`  | Integer |
| `ec2_instance_older_than_specific_days` | `max_ec2_instance_age_in_days`  | Integer |
| `vpc_endpoint_connections_trust_boundaries`  | `trusted_account_ids`  | List of Strings |
| `vpc_endpoint_services_allowed_principals_trust_boundaries`  | `trusted_account_ids`  | List of Strings |
| `cloudwatch_log_group_retention_policy_specific_days_enabled` | `log_group_retention_days` | Integer |
| `appstream_fleet_session_idle_disconnect_timeout`  | `max_idle_disconnect_timeout_in_seconds`  | Integer |
| `appstream_fleet_session_disconnect_timeout`  |  `max_disconnect_timeout_in_seconds` | Integer |
| `appstream_fleet_maximum_session_duration`  | `max_session_duration_seconds`  | Integer |
| `awslambda_function_using_supported_runtimes` | `obsolete_lambda_runtimes`  | Integer |
| `organizations_scp_check_deny_regions` | `organizations_enabled_regions`  | List of Strings |
| `organizations_delegated_administrators` |  `organizations_trusted_delegated_administrators` | List of Strings |

## Azure

### Configurable Checks

## GCP

### Configurable Checks

## Config YAML File Structure
> This is the new Prowler configuration file format. The old one without provider keys is still compatible just for the AWS provider.

```yaml title="config.yaml"
# AWS Configuration
aws:
  # AWS EC2 Configuration
  # aws.ec2_elastic_ip_shodan
  shodan_api_key: null
  # aws.ec2_securitygroup_with_many_ingress_egress_rules --> by default is 50 rules
  max_security_group_rules: 50
  # aws.ec2_instance_older_than_specific_days --> by default is 6 months (180 days)
  max_ec2_instance_age_in_days: 180

  # AWS VPC Configuration (vpc_endpoint_connections_trust_boundaries, vpc_endpoint_services_allowed_principals_trust_boundaries)
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
      "python3.6",
      "python2.7",
      "nodejs4.3",
      "nodejs4.3-edge",
      "nodejs6.10",
      "nodejs",
      "nodejs8.10",
      "nodejs10.x",
      "dotnetcore1.0",
      "dotnetcore2.0",
      "dotnetcore2.1",
      "ruby2.5",
    ]

  # AWS Organizations
  # organizations_scp_check_deny_regions
  # organizations_enabled_regions: [
  #   'eu-central-1',
  #   'eu-west-1',
  #   "us-east-1"
  # ]
  organizations_enabled_regions: []
  organizations_trusted_delegated_administrators: []

# Azure Configuration
azure:

# GCP Configuration
gcp:

```
