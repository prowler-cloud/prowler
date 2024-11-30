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
| `acm_certificates_expiration_check`                           | `days_to_expire_threshold`                       | Integer         |
| `appstream_fleet_maximum_session_duration`                    | `max_session_duration_seconds`                   | Integer         |
| `appstream_fleet_session_disconnect_timeout`                  | `max_disconnect_timeout_in_seconds`              | Integer         |
| `appstream_fleet_session_idle_disconnect_timeout`             | `max_idle_disconnect_timeout_in_seconds`         | Integer         |
| `autoscaling_find_secrets_ec2_launch_configuration`           | `secrets_ignore_patterns`                        | List of Strings |
| `awslambda_function_no_secrets_in_code`                       | `secrets_ignore_patterns`                        | List of Strings |
| `awslambda_function_no_secrets_in_variables`                  | `secrets_ignore_patterns`                        | List of Strings |
| `awslambda_function_using_supported_runtimes`                 | `obsolete_lambda_runtimes`                       | Integer         |
| `awslambda_function_vpc_is_in_multi_azs`                      | `lambda_min_azs`                                 | Integer         |
| `cloudformation_stack_outputs_find_secrets`                   | `secrets_ignore_patterns`                        | List of Strings |
| `cloudtrail_threat_detection_enumeration`                     | `threat_detection_enumeration_actions`           | List of Strings |
| `cloudtrail_threat_detection_enumeration`                     | `threat_detection_enumeration_entropy`           | Integer         |
| `cloudtrail_threat_detection_enumeration`                     | `threat_detection_enumeration_minutes`           | Integer         |
| `cloudtrail_threat_detection_privilege_escalation`            | `threat_detection_privilege_escalation_actions`  | List of Strings |
| `cloudtrail_threat_detection_privilege_escalation`            | `threat_detection_privilege_escalation_entropy`  | Integer         |
| `cloudtrail_threat_detection_privilege_escalation`            | `threat_detection_privilege_escalation_minutes`  | Integer         |
| `cloudwatch_log_group_no_secrets_in_logs`                     | `secrets_ignore_patterns`                        | List of Strings |
| `cloudwatch_log_group_retention_policy_specific_days_enabled` | `log_group_retention_days`                       | Integer         |
| `codebuild_project_no_secrets_in_variables`                   | `excluded_sensitive_environment_variables`       | List of Strings |
| `codebuild_project_no_secrets_in_variables`                   | `secrets_ignore_patterns`                        | List of Strings |
| `config_recorder_all_regions_enabled`                         | `mute_non_default_regions`                       | Boolean         |
| `drs_job_exist`                                               | `mute_non_default_regions`                       | Boolean         |
| `ec2_elastic_ip_shodan`                                       | `shodan_api_key`                                 | String          |
| `ec2_instance_older_than_specific_days`                       | `max_ec2_instance_age_in_days`                   | Integer         |
| `ec2_instance_secrets_user_data`                              | `secrets_ignore_patterns`                        | List of Strings |
| `ec2_launch_template_no_secrets`                              | `secrets_ignore_patterns`                        | List of Strings |
| `ec2_securitygroup_allow_ingress_from_internet_to_any_port`   | `ec2_allowed_instance_owners`                    | List of Strings |
| `ec2_securitygroup_allow_ingress_from_internet_to_any_port`   | `ec2_allowed_interface_types`                    | List of Strings |
| `ec2_securitygroup_allow_ingress_from_internet_to_high_risk_tcp_ports`| `ec2_high_risk_ports`                    | List of Integer |
| `ec2_securitygroup_with_many_ingress_egress_rules`            | `max_security_group_rules`                       | Integer         |
| `ecs_task_definitions_no_environment_secrets`                 | `secrets_ignore_patterns`                        | List of Strings |
| `ecr_repositories_scan_vulnerabilities_in_latest_image`       | `ecr_repository_vulnerability_minimum_severity`  | String          |
| `eks_cluster_uses_a_supported_version`                        | `eks_cluster_oldest_version_supported`           | String          |
| `eks_control_plane_logging_all_types_enabled`                 | `eks_required_log_types`                         | List of Strings |
| `elb_is_in_multiple_az`                                       | `elb_min_azs`                                    | Integer         |
| `elbv2_is_in_multiple_az`                                     | `elbv2_min_azs`                                  | Integer         |
| `guardduty_is_enabled`                                        | `mute_non_default_regions`                       | Boolean         |
| `iam_user_accesskey_unused`                                   | `max_unused_access_keys_days`                    | Integer         |
| `iam_user_console_access_unused`                              | `max_console_access_days`                        | Integer         |
| `organizations_delegated_administrators`                      | `organizations_trusted_delegated_administrators` | List of Strings |
| `organizations_scp_check_deny_regions`                        | `organizations_enabled_regions`                  | List of Strings |
| `rds_instance_backup_enabled`                                 | `check_rds_instance_replicas`                    | Boolean         |
| `securityhub_enabled`                                         | `mute_non_default_regions`                       | Boolean         |
| `secretsmanager_secret_unused`                                | `max_days_secret_unused`                         | Integer         |
| `secretsmanager_secret_rotated_periodically`                  | `max_days_secret_unrotated`                      | Integer         |
| `ssm_document_secrets`                                        | `secrets_ignore_patterns`                        | List of Strings |
| `trustedadvisor_premium_support_plan_subscribed`              | `verify_premium_support_plans`                   | Boolean         |
| `vpc_endpoint_connections_trust_boundaries`                   | `trusted_account_ids`                            | List of Strings |
| `vpc_endpoint_services_allowed_principals_trust_boundaries`   | `trusted_account_ids`                            | List of Strings |


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
  # aws.mute_non_default_regions --> Set to True to muted failed findings in non-default regions for AccessAnalyzer, GuardDuty, SecurityHub, DRS and Config
  mute_non_default_regions: False
  # If you want to mute failed findings only in specific regions, create a file with the following syntax and run it with `prowler aws -w mutelist.yaml`:
  # Mutelist:
  #  Accounts:
  #   "*":
  #     Checks:
  #       "*":
  #         Regions:
  #           - "ap-southeast-1"
  #           - "ap-southeast-2"
  #         Resources:
  #           - "*"

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
  # aws.ec2_securitygroup_allow_ingress_from_internet_to_high_risk_tcp_ports
  ec2_high_risk_ports:
    [
        25,
        110,
        135,
        143,
        445,
        3000,
        4333,
        5000,
        5500,
        8080,
        8088,
    ]

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

  # AWS CloudTrail Configuration
  # aws.cloudtrail_threat_detection_privilege_escalation
  threat_detection_privilege_escalation_threshold: 0.2 # Percentage of actions found to decide if it is an privilege_escalation attack event, by default is 0.2 (20%)
  threat_detection_privilege_escalation_minutes: 1440 # Past minutes to search from now for privilege_escalation attacks, by default is 1440 minutes (24 hours)
  threat_detection_privilege_escalation_actions:
    [
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
  threat_detection_enumeration_threshold: 0.3 # Percentage of actions found to decide if it is an enumeration attack event, by default is 0.3 (30%)
  threat_detection_enumeration_minutes: 1440 # Past minutes to search from now for enumeration attacks, by default is 1440 minutes (24 hours)
  threat_detection_enumeration_actions:
    [
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
  # aws.cloudtrail_threat_detection_llm_jacking
  threat_detection_llm_jacking_threshold: 0.4 # Percentage of actions found to decide if it is an LLM Jacking attack event, by default is 0.4 (40%)
  threat_detection_llm_jacking_minutes: 1440 # Past minutes to search from now for LLM Jacking attacks, by default is 1440 minutes (24 hours)
  threat_detection_llm_jacking_actions:
    [
    "PutUseCaseForModelAccess",  # Submits a use case for model access, providing justification (Write).
    "PutFoundationModelEntitlement",  # Grants entitlement for accessing a foundation model (Write).
    "PutModelInvocationLoggingConfiguration", # Configures logging for model invocations (Write).
    "CreateFoundationModelAgreement",  # Creates a new agreement to use a foundation model (Write).
    "InvokeModel",  # Invokes a specified Bedrock model for inference using provided prompt and parameters (Read).
    "InvokeModelWithResponseStream",  # Invokes a Bedrock model for inference with real-time token streaming (Read).
    "GetUseCaseForModelAccess",  # Retrieves an existing use case for model access (Read).
    "GetModelInvocationLoggingConfiguration",  # Fetches the logging configuration for model invocations (Read).
    "GetFoundationModelAvailability",  # Checks the availability of a foundation model for use (Read).
    "ListFoundationModelAgreementOffers",  # Lists available agreement offers for accessing foundation models (List).
    "ListFoundationModels",  # Lists the available foundation models in Bedrock (List).
    "ListProvisionedModelThroughputs",  # Lists the provisioned throughput for previously created models (List).
    ]

  # AWS RDS Configuration
  # aws.rds_instance_backup_enabled
  # Whether to check RDS instance replicas or not
  check_rds_instance_replicas: False

  # AWS ACM Configuration
  # aws.acm_certificates_expiration_check
  days_to_expire_threshold: 7

  # AWS EKS Configuration
  # aws.eks_control_plane_logging_all_types_enabled
  # EKS control plane logging types that must be enabled
  eks_required_log_types:
    [
      "api",
      "audit",
      "authenticator",
      "controllerManager",
      "scheduler",
    ]

  # aws.eks_cluster_uses_a_supported_version
  # EKS clusters must be version 1.28 or higher
  eks_cluster_oldest_version_supported: "1.28"

  # AWS CodeBuild Configuration
  # aws.codebuild_project_no_secrets_in_variables
  # CodeBuild sensitive variables that are excluded from the check
  excluded_sensitive_environment_variables:
    [

    ]

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

# Kubernetes Configuration
kubernetes:
  # Kubernetes API Server
  # kubernetes.apiserver_audit_log_maxbackup_set
  audit_log_maxbackup: 10
  # kubernetes.apiserver_audit_log_maxsize_set
  audit_log_maxsize: 100
  # kubernetes.apiserver_audit_log_maxage_set
  audit_log_maxage: 30
  # kubernetes.apiserver_strong_ciphers_only
  apiserver_strong_ciphers:
    [
      "TLS_AES_128_GCM_SHA256",
      "TLS_AES_256_GCM_SHA384",
      "TLS_CHACHA20_POLY1305_SHA256",
    ]
  # Kubelet
  # kubernetes.kubelet_strong_ciphers_only
  kubelet_strong_ciphers:
    [
      "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
      "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
      "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305",
      "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
      "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305",
      "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
      "TLS_RSA_WITH_AES_256_GCM_SHA384",
      "TLS_RSA_WITH_AES_128_GCM_SHA256",
    ]

```
