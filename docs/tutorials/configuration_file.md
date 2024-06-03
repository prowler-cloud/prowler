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
| `config_recorder_all_regions_enabled`                         | `mute_non_default_regions`                  | Boolean         |
| `drs_job_exist`                                               | `mute_non_default_regions`                  | Boolean         |
| `guardduty_is_enabled`                                        | `mute_non_default_regions`                  | Boolean         |
| `securityhub_enabled`                                         | `mute_non_default_regions`                  | Boolean         |
| `cloudtrail_threat_detection_privilege_escalation`             | `threat_detection_privilege_escalation_entropy` | Integer         |
| `cloudtrail_threat_detection_privilege_escalation`             | `threat_detection_privilege_escalation_minutes` | Integer         |
| `cloudtrail_threat_detection_privilege_escalation`             | `threat_detection_privilege_escalation_actions` | List of Strings         |
| `cloudtrail_threat_detection_enumeration`                      | `threat_detection_enumeration_entropy`      | Integer         |
| `cloudtrail_threat_detection_enumeration`                      | `threat_detection_enumeration_minutes`      | Integer         |
| `cloudtrail_threat_detection_enumeration`                      | `threat_detection_enumeration_actions`      | List of Strings         |
| `rds_instance_backup_enabled`                                  | `check_rds_instance_replicas`      | Boolean        |
| `ec2_securitygroup_allow_ingress_from_internet_to_any_port`    | `ec2_allowed_interface_types`      | List of Strings        |
| `ec2_securitygroup_allow_ingress_from_internet_to_any_port`    | `ec2_allowed_instance_owners`      | List of Strings        |
## Azure

### Configurable Checks
The following list includes all the Azure checks with configurable variables that can be changed in the configuration yaml file:

| Check Name                                                    | Value                                            | Type            |
|---------------------------------------------------------------|--------------------------------------------------|-----------------|
| `network_public_ip_shodan`                                    | `shodan_api_key`                                 | String          |
| `app_ensure_php_version_is_latest`                            | `php_latest_version`                             | String          |
| `app_ensure_python_version_is_latest`                         | `python_latest_version`                          | String          |
| `app_ensure_java_version_is_latest`                           | `java_latest_version`                            | String          |


## GCP

### Configurable Checks

## Kubernetes

### Configurable Checks
The following list includes all the Azure checks with configurable variables that can be changed in the configuration yaml file:

| Check Name                                                    | Value                                            | Type            |
|---------------------------------------------------------------|--------------------------------------------------|-----------------|
| `audit_log_maxbackup`                                         | `audit_log_maxbackup`                            | String          |
| `audit_log_maxsize`                                           | `audit_log_maxsize`                              | String          |
| `audit_log_maxage`                                            | `audit_log_maxage`                               | String          |
| `apiserver_strong_ciphers`                                    | `apiserver_strong_ciphers`                       | String          |
| `kubelet_strong_ciphers_only`                                 | `kubelet_strong_ciphers`                         | String          |

## Config YAML File Structure

???+ note
    This is the new Prowler configuration file format. The old one without provider keys is still compatible just for the AWS provider.

```yaml title="config.yaml"
# AWS Configuration
aws:

  # AWS Global Configuration
  # aws.mute_non_default_regions --> Mute Failed Findings in non-default regions for GuardDuty, SecurityHub, DRS and Config
  mute_non_default_regions: False

  # AWS IAM Configuration
  # aws.iam_user_accesskey_unused --> CIS recommends 45 days
  max_unused_access_keys_days: 45
  # aws.iam_user_console_access_unused --> CIS recommends 45 days
  max_console_access_days: 45

  # AWS EC2 Configuration
  # aws.ec2_elastic_ip_shodan
  shodan_api_key: null
  # aws.ec2_securitygroup_with_many_ingress_egress_rules --> by default is 50 rules
  max_security_group_rules: 50
  # aws.ec2_instance_older_than_specific_days --> by default is 6 months (180 days)
  max_ec2_instance_age_in_days: 180
  # aws.ec2_securitygroup_allow_ingress_from_internet_to_any_port
  # allowed network interface types for security groups open to the Internet
  ec2_allowed_interface_types:
    [
      "api_gateway_managed",
      "vpc_endpoint",
    ]
  # allowed network interface owners for security groups open to the Internet
  ec2_allowed_instance_owners:
    [
      "amazon-elb"
    ]

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

  # AWS ECR
  # ecr_repositories_scan_vulnerabilities_in_latest_image
  # CRITICAL
  # HIGH
  # MEDIUM
  ecr_repository_vulnerability_minimum_severity: "MEDIUM"

  # AWS Trusted Advisor
  # trustedadvisor_premium_support_plan_subscribed
  verify_premium_support_plans: True

  # AWS CloudTrail Configuration
  # aws.cloudtrail_threat_detection_privilege_escalation
  threat_detection_privilege_escalation_entropy: 0.7 # Percentage of actions found to decide if it is an privilege_escalation attack event, by default is 0.7 (70%)
  threat_detection_privilege_escalation_minutes: 1440 # Past minutes to search from now for privilege_escalation attacks, by default is 1440 minutes (24 hours)
  threat_detection_privilege_escalation_actions: [
    "AddPermission",
    "AddRoleToInstanceProfile",
    "AddUserToGroup",
    "AssociateAccessPolicy",
    "AssumeRole",
    "AttachGroupPolicy",
    "AttachRolePolicy",
    "AttachUserPolicy",
    "ChangePassword",
    "CreateAccessEntry",
    "CreateAccessKey",
    "CreateDevEndpoint",
    "CreateEventSourceMapping",
    "CreateFunction",
    "CreateGroup",
    "CreateJob",
    "CreateKeyPair",
    "CreateLoginProfile",
    "CreatePipeline",
    "CreatePolicyVersion",
    "CreateRole",
    "CreateStack",
    "DeleteRolePermissionsBoundary",
    "DeleteRolePolicy",
    "DeleteUserPermissionsBoundary",
    "DeleteUserPolicy",
    "DetachRolePolicy",
    "DetachUserPolicy",
    "GetCredentialsForIdentity",
    "GetId",
    "GetPolicyVersion",
    "GetUserPolicy",
    "Invoke",
    "ModifyInstanceAttribute",
    "PassRole",
    "PutGroupPolicy",
    "PutPipelineDefinition",
    "PutRolePermissionsBoundary",
    "PutRolePolicy",
    "PutUserPermissionsBoundary",
    "PutUserPolicy",
    "ReplaceIamInstanceProfileAssociation",
    "RunInstances",
    "SetDefaultPolicyVersion",
    "UpdateAccessKey",
    "UpdateAssumeRolePolicy",
    "UpdateDevEndpoint",
    "UpdateEventSourceMapping",
    "UpdateFunctionCode",
    "UpdateJob",
    "UpdateLoginProfile",
  ]
  # aws.cloudtrail_threat_detection_enumeration
  threat_detection_enumeration_entropy: 0.7 # Percentage of actions found to decide if it is an enumeration attack event, by default is 0.7 (70%)
  threat_detection_enumeration_minutes: 1440 # Past minutes to search from now for enumeration attacks, by default is 1440 minutes (24 hours)
  threat_detection_enumeration_actions: [
    "DescribeAccessEntry",
    "DescribeAccountAttributes",
    "DescribeAvailabilityZones",
    "DescribeBundleTasks",
    "DescribeCarrierGateways",
    "DescribeClientVpnRoutes",
    "DescribeCluster",
    "DescribeDhcpOptions",
    "DescribeFlowLogs",
    "DescribeImages",
    "DescribeInstanceAttribute",
    "DescribeInstanceInformation",
    "DescribeInstanceTypes",
    "DescribeInstances",
    "DescribeInstances",
    "DescribeKeyPairs",
    "DescribeLogGroups",
    "DescribeLogStreams",
    "DescribeOrganization",
    "DescribeRegions",
    "DescribeSecurityGroups",
    "DescribeSnapshotAttribute",
    "DescribeSnapshotTierStatus",
    "DescribeSubscriptionFilters",
    "DescribeTransitGatewayMulticastDomains",
    "DescribeVolumes",
    "DescribeVolumesModifications",
    "DescribeVpcEndpointConnectionNotifications",
    "DescribeVpcs",
    "GetAccount",
    "GetAccountAuthorizationDetails",
    "GetAccountSendingEnabled",
    "GetBucketAcl",
    "GetBucketLogging",
    "GetBucketPolicy",
    "GetBucketReplication",
    "GetBucketVersioning",
    "GetCallerIdentity",
    "GetCertificate",
    "GetConsoleScreenshot",
    "GetCostAndUsage",
    "GetDetector",
    "GetEbsDefaultKmsKeyId",
    "GetEbsEncryptionByDefault",
    "GetFindings",
    "GetFlowLogsIntegrationTemplate",
    "GetIdentityVerificationAttributes",
    "GetInstances",
    "GetIntrospectionSchema",
    "GetLaunchTemplateData",
    "GetLaunchTemplateData",
    "GetLogRecord",
    "GetParameters",
    "GetPolicyVersion",
    "GetPublicAccessBlock",
    "GetQueryResults",
    "GetRegions",
    "GetSMSAttributes",
    "GetSMSSandboxAccountStatus",
    "GetSendQuota",
    "GetTransitGatewayRouteTableAssociations",
    "GetUserPolicy",
    "HeadObject",
    "ListAccessKeys",
    "ListAccounts",
    "ListAllMyBuckets",
    "ListAssociatedAccessPolicies",
    "ListAttachedUserPolicies",
    "ListClusters",
    "ListDetectors",
    "ListDomains",
    "ListFindings",
    "ListHostedZones",
    "ListIPSets",
    "ListIdentities",
    "ListInstanceProfiles",
    "ListObjects",
    "ListOrganizationalUnitsForParent",
    "ListOriginationNumbers",
    "ListPolicyVersions",
    "ListRoles",
    "ListRoles",
    "ListRules",
    "ListServiceQuotas",
    "ListSubscriptions",
    "ListTargetsByRule",
    "ListTopics",
    "ListUsers",
    "LookupEvents",
    "Search",
  ]

  # aws.rds_instance_backup_enabled
  # Whether to check RDS instance replicas or not
  check_rds_instance_replicas: False

# Azure Configuration
azure:
  # Azure Network Configuration
  # azure.network_public_ip_shodan
  shodan_api_key: null

  # Azure App Configuration
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
