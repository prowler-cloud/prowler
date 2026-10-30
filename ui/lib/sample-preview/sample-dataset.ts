import type { AttackSurfaceId } from "@/actions/overview/attack-surface/attack-surface.adapter";
import { RESOURCE_GROUP_IDS } from "@/actions/overview/resources-inventory/resources-inventory.adapter";
import { SEVERITY, type Severity } from "@/types/components";

// One demo AWS account, described once. Every sample page derives its numbers
// from SAMPLE_CHECKS, so the Overview totals, the findings list and the issues
// always agree with each other.

export const SAMPLE_ACCOUNT = {
  uid: "123456789012",
  alias: "Sample AWS account",
  providerId: "sample-provider",
  scanId: "sample-scan",
  scannedAt: "2026-10-28T09:12:00Z",
} as const;

export const SAMPLE_REGIONS = [
  "us-east-1",
  "us-west-2",
  "eu-west-1",
  "eu-central-1",
] as const;

type ResourceGroupId =
  (typeof RESOURCE_GROUP_IDS)[keyof typeof RESOURCE_GROUP_IDS];

export interface SampleCheck {
  checkId: string;
  title: string;
  service: string;
  severity: Severity;
  resourceGroup: ResourceGroupId;
  failed: number;
  passed: number;
  // Failed findings that the latest scan saw for the first time.
  newFailed: number;
  attackSurface?: AttackSurfaceId;
}

export const SAMPLE_CHECKS: SampleCheck[] = [
  {
    checkId: "s3_bucket_public_access",
    title: "Ensure S3 buckets are not publicly accessible",
    service: "s3",
    severity: SEVERITY.CRITICAL,
    resourceGroup: RESOURCE_GROUP_IDS.STORAGE,
    failed: 3,
    passed: 21,
    newFailed: 1,
    attackSurface: "internet-exposed",
  },
  {
    checkId: "iam_root_mfa_enabled",
    title: "Ensure MFA is enabled for the root account",
    service: "iam",
    severity: SEVERITY.CRITICAL,
    resourceGroup: RESOURCE_GROUP_IDS.IAM,
    failed: 1,
    passed: 0,
    newFailed: 0,
  },
  {
    checkId: "rds_instance_no_public_access",
    title: "Ensure RDS instances are not publicly accessible",
    service: "rds",
    severity: SEVERITY.CRITICAL,
    resourceGroup: RESOURCE_GROUP_IDS.DATABASE,
    failed: 1,
    passed: 5,
    newFailed: 1,
    attackSurface: "internet-exposed",
  },
  {
    checkId: "awslambda_function_no_secrets_in_variables",
    title: "Find secrets in Lambda function environment variables",
    service: "awslambda",
    severity: SEVERITY.CRITICAL,
    resourceGroup: RESOURCE_GROUP_IDS.SERVERLESS,
    failed: 2,
    passed: 10,
    newFailed: 0,
    attackSurface: "secrets",
  },
  {
    checkId: "ec2_instance_secrets_user_data",
    title: "Find secrets in EC2 user data",
    service: "ec2",
    severity: SEVERITY.CRITICAL,
    resourceGroup: RESOURCE_GROUP_IDS.COMPUTE,
    failed: 1,
    passed: 11,
    newFailed: 0,
    attackSurface: "secrets",
  },
  {
    checkId: "ec2_securitygroup_allow_ingress_from_internet_to_tcp_port_22",
    title:
      "Ensure no security groups allow ingress from 0.0.0.0/0 or ::/0 to SSH port 22",
    service: "ec2",
    severity: SEVERITY.HIGH,
    resourceGroup: RESOURCE_GROUP_IDS.NETWORK,
    failed: 4,
    passed: 38,
    newFailed: 2,
    attackSurface: "internet-exposed",
  },
  {
    checkId: "iam_policy_allows_privilege_escalation",
    title: "Ensure no custom IAM policies allow privilege escalation",
    service: "iam",
    severity: SEVERITY.HIGH,
    resourceGroup: RESOURCE_GROUP_IDS.IAM,
    failed: 2,
    passed: 14,
    newFailed: 0,
    attackSurface: "privilege-escalation",
  },
  {
    checkId: "cloudtrail_multi_region_enabled",
    title: "Ensure CloudTrail is enabled in all regions",
    service: "cloudtrail",
    severity: SEVERITY.HIGH,
    resourceGroup: RESOURCE_GROUP_IDS.MONITORING,
    failed: 1,
    passed: 0,
    newFailed: 0,
  },
  {
    checkId: "iam_user_mfa_enabled_console_access",
    title: "Ensure MFA is enabled for all IAM users with console access",
    service: "iam",
    severity: SEVERITY.HIGH,
    resourceGroup: RESOURCE_GROUP_IDS.IAM,
    failed: 3,
    passed: 6,
    newFailed: 1,
  },
  {
    checkId: "eks_cluster_not_publicly_accessible",
    title: "Ensure EKS clusters are not publicly accessible",
    service: "eks",
    severity: SEVERITY.HIGH,
    resourceGroup: RESOURCE_GROUP_IDS.CONTAINER,
    failed: 1,
    passed: 1,
    newFailed: 0,
    attackSurface: "internet-exposed",
  },
  {
    checkId: "ec2_instance_imdsv2_enabled",
    title: "Ensure EC2 instances require IMDSv2",
    service: "ec2",
    severity: SEVERITY.MEDIUM,
    resourceGroup: RESOURCE_GROUP_IDS.COMPUTE,
    failed: 7,
    passed: 5,
    newFailed: 2,
    attackSurface: "ec2-imdsv1",
  },
  {
    checkId: "ec2_ebs_volume_encryption",
    title: "Ensure EBS volumes are encrypted",
    service: "ec2",
    severity: SEVERITY.MEDIUM,
    resourceGroup: RESOURCE_GROUP_IDS.STORAGE,
    failed: 9,
    passed: 14,
    newFailed: 1,
  },
  {
    checkId: "s3_bucket_secure_transport_policy",
    title: "Ensure S3 buckets enforce encryption in transit",
    service: "s3",
    severity: SEVERITY.MEDIUM,
    resourceGroup: RESOURCE_GROUP_IDS.STORAGE,
    failed: 11,
    passed: 13,
    newFailed: 0,
  },
  {
    checkId: "iam_rotate_access_key_90_days",
    title: "Ensure access keys are rotated every 90 days or less",
    service: "iam",
    severity: SEVERITY.MEDIUM,
    resourceGroup: RESOURCE_GROUP_IDS.IAM,
    failed: 5,
    passed: 7,
    newFailed: 0,
  },
  {
    checkId: "guardduty_is_enabled",
    title: "Ensure Amazon GuardDuty is enabled",
    service: "guardduty",
    severity: SEVERITY.MEDIUM,
    resourceGroup: RESOURCE_GROUP_IDS.SECURITY,
    failed: 3,
    passed: 1,
    newFailed: 0,
  },
  {
    checkId: "config_recorder_all_regions_enabled",
    title: "Ensure AWS Config is enabled in all regions",
    service: "config",
    severity: SEVERITY.MEDIUM,
    resourceGroup: RESOURCE_GROUP_IDS.GOVERNANCE,
    failed: 3,
    passed: 1,
    newFailed: 0,
  },
  {
    checkId: "vpc_flow_logs_enabled",
    title: "Ensure VPC Flow Logs are enabled in all VPCs",
    service: "vpc",
    severity: SEVERITY.MEDIUM,
    resourceGroup: RESOURCE_GROUP_IDS.NETWORK,
    failed: 4,
    passed: 0,
    newFailed: 0,
  },
  {
    checkId: "kms_cmk_rotation_enabled",
    title: "Ensure rotation is enabled for customer managed KMS keys",
    service: "kms",
    severity: SEVERITY.MEDIUM,
    resourceGroup: RESOURCE_GROUP_IDS.SECURITY,
    failed: 3,
    passed: 4,
    newFailed: 0,
  },
  {
    checkId: "apigateway_restapi_logging_enabled",
    title: "Ensure API Gateway REST API stages have logging enabled",
    service: "apigateway",
    severity: SEVERITY.LOW,
    resourceGroup: RESOURCE_GROUP_IDS.API_GATEWAY,
    failed: 2,
    passed: 1,
    newFailed: 0,
  },
  {
    checkId: "sqs_queues_server_side_encryption_enabled",
    title: "Ensure SQS queues have server-side encryption enabled",
    service: "sqs",
    severity: SEVERITY.LOW,
    resourceGroup: RESOURCE_GROUP_IDS.MESSAGING,
    failed: 3,
    passed: 2,
    newFailed: 0,
  },
  {
    checkId: "cloudwatch_log_metric_filter_root_usage",
    title: "Ensure a log metric filter and alarm exist for root account usage",
    service: "cloudwatch",
    severity: SEVERITY.LOW,
    resourceGroup: RESOURCE_GROUP_IDS.MONITORING,
    failed: 1,
    passed: 0,
    newFailed: 0,
  },
  {
    checkId: "ec2_instance_managed_by_ssm",
    title: "Ensure EC2 instances are managed by Systems Manager",
    service: "ssm",
    severity: SEVERITY.LOW,
    resourceGroup: RESOURCE_GROUP_IDS.COMPUTE,
    failed: 4,
    passed: 8,
    newFailed: 0,
  },
  {
    checkId: "account_maintain_current_contact_details",
    title: "Maintain current contact details for the AWS account",
    service: "account",
    severity: SEVERITY.INFORMATIONAL,
    resourceGroup: RESOURCE_GROUP_IDS.GOVERNANCE,
    failed: 1,
    passed: 0,
    newFailed: 0,
  },
];

export const SAMPLE_FAILED_CHECKS = SAMPLE_CHECKS.filter(
  (check) => check.failed > 0,
);
