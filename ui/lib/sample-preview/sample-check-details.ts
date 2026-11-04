// What the finding drawer shows for each sample check: the check metadata a
// real scan stores on every finding, and the status line per resource.

/** A framework of the sample watchlist (see SAMPLE_COMPLIANCE_WATCHLIST_RESPONSE). */
export interface SampleFramework {
  complianceId: string;
  framework: string;
  name: string;
  version: string;
}

export interface SampleCheckDetail {
  description: string;
  risk: string;
  recommendation: string;
  cli?: string;
  /** Status line of a failed finding; `{name}` is the resource name. */
  fail: string;
  pass: string;
  compliance: SampleFramework[];
}

const CIS: SampleFramework = {
  complianceId: "cis_5.0_aws",
  framework: "CIS",
  name: "CIS Amazon Web Services Foundations Benchmark",
  version: "5.0",
};
const FSBP: SampleFramework = {
  complianceId: "aws_foundational_security_best_practices_aws",
  framework: "AWS-Foundational-Security-Best-Practices",
  name: "AWS Foundational Security Best Practices",
  version: "",
};
const PCI: SampleFramework = {
  complianceId: "pci_4.0_aws",
  framework: "PCI-DSS",
  name: "PCI DSS",
  version: "4.0",
};
const ISO: SampleFramework = {
  complianceId: "iso27001_2022_aws",
  framework: "ISO27001",
  name: "ISO/IEC 27001",
  version: "2022",
};
const SOC2: SampleFramework = {
  complianceId: "soc2_aws",
  framework: "SOC2",
  name: "SOC 2",
  version: "",
};

export const SAMPLE_CHECK_DETAILS: Record<string, SampleCheckDetail> = {
  s3_bucket_public_access: {
    description:
      "Checks whether the bucket policy or ACL grants access to everyone.",
    risk: "Anyone on the internet can list and download the objects, which leaks whatever the bucket stores.",
    recommendation:
      "Turn on S3 Block Public Access for the bucket and remove public grants from its policy and ACL.",
    cli: "aws s3api put-public-access-block --bucket {name} --public-access-block-configuration BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true",
    fail: "S3 Bucket {name} has a bucket policy that allows public access.",
    pass: "S3 Bucket {name} is not publicly accessible.",
    compliance: [CIS, FSBP, PCI, ISO, SOC2],
  },
  iam_root_mfa_enabled: {
    description: "Checks whether the root user has an MFA device.",
    risk: "A leaked root password gives full control of the account, billing included, with nothing else in the way.",
    recommendation:
      "Enable a hardware or virtual MFA device for the root user and stop using it for daily work.",
    fail: "MFA is not enabled for the root account.",
    pass: "MFA is enabled for the root account.",
    compliance: [CIS, FSBP, PCI, ISO, SOC2],
  },
  rds_instance_no_public_access: {
    description: "Checks whether the RDS instance is publicly accessible.",
    risk: "A public database endpoint is exposed to brute force and to any credential that leaks.",
    recommendation:
      "Set PubliclyAccessible to false and reach the database through private subnets.",
    cli: "aws rds modify-db-instance --db-instance-identifier {name} --no-publicly-accessible --apply-immediately",
    fail: "RDS Instance {name} is set as publicly accessible.",
    pass: "RDS Instance {name} is not publicly accessible.",
    compliance: [FSBP, PCI, ISO],
  },
  awslambda_function_no_secrets_in_variables: {
    description: "Looks for secrets in the function's environment variables.",
    risk: "Anyone who can read the function configuration gets the credentials in plain text.",
    recommendation:
      "Store the secret in Secrets Manager, read it at runtime and rotate the exposed value.",
    fail: "Potential secret found in Lambda function {name} variables -> DB_PASSWORD.",
    pass: "No secrets found in Lambda function {name} variables.",
    compliance: [FSBP, PCI, SOC2],
  },
  ec2_instance_secrets_user_data: {
    description: "Looks for secrets in the instance user data.",
    risk: "User data is readable from the instance and through the EC2 API, so the secret is effectively public inside the account.",
    recommendation:
      "Remove the secret from user data and fetch it from Secrets Manager or Parameter Store at boot.",
    fail: "Potential secret found in EC2 instance {name} User Data -> AWS_SECRET_ACCESS_KEY.",
    pass: "No secrets found in EC2 instance {name} User Data.",
    compliance: [FSBP, PCI],
  },
  ec2_securitygroup_allow_ingress_from_internet_to_tcp_port_22: {
    description:
      "Checks whether the security group allows SSH from 0.0.0.0/0 or ::/0.",
    risk: "SSH open to the internet invites brute force and exploitation of any SSH vulnerability.",
    recommendation:
      "Restrict port 22 to known addresses, or drop SSH and use Session Manager.",
    cli: "aws ec2 revoke-security-group-ingress --group-id {name} --protocol tcp --port 22 --cidr 0.0.0.0/0",
    fail: "Security group {name} has SSH port 22 open to the Internet.",
    pass: "Security group {name} does not have SSH port 22 open to the Internet.",
    compliance: [CIS, FSBP, PCI, ISO],
  },
  iam_policy_allows_privilege_escalation: {
    description:
      "Checks whether a customer managed policy grants actions that let a principal raise its own privileges.",
    risk: "A principal with this policy can attach admin policies or pass privileged roles to itself.",
    recommendation:
      "Remove iam:PassRole, iam:AttachUserPolicy and similar actions, or scope them to specific resources.",
    fail: "Custom Policy {name} allows privilege escalation using the following actions: iam:PassRole, iam:AttachRolePolicy.",
    pass: "Custom Policy {name} does not allow privilege escalation.",
    compliance: [FSBP, ISO, SOC2],
  },
  cloudtrail_multi_region_enabled: {
    description: "Checks whether a CloudTrail trail logs every region.",
    risk: "Activity in regions without a trail leaves no audit record.",
    recommendation: "Create a multi-region trail that logs management events.",
    cli: "aws cloudtrail update-trail --name {name} --is-multi-region-trail",
    fail: "No CloudTrail trails enabled with logging were found in some regions.",
    pass: "Trail {name} is multiregion and it is logging.",
    compliance: [CIS, FSBP, PCI, ISO, SOC2],
  },
  iam_user_mfa_enabled_console_access: {
    description: "Checks whether IAM users with a console password have MFA.",
    risk: "A phished or reused password is enough to sign in to the console.",
    recommendation:
      "Require MFA for every user with console access, or move them to IAM Identity Center.",
    fail: "User {name} has Console Password enabled but MFA disabled.",
    pass: "User {name} has Console Password enabled and MFA enabled.",
    compliance: [CIS, FSBP, PCI, ISO, SOC2],
  },
  eks_cluster_not_publicly_accessible: {
    description:
      "Checks whether the EKS API endpoint is reachable from the internet.",
    risk: "A public control plane is exposed to credential stuffing and API vulnerabilities.",
    recommendation:
      "Disable public endpoint access or restrict it to known CIDR blocks.",
    fail: "EKS cluster {name} is publicly accessible.",
    pass: "EKS cluster {name} is not publicly accessible.",
    compliance: [FSBP, ISO],
  },
  ec2_instance_imdsv2_enabled: {
    description: "Checks whether the instance requires IMDSv2.",
    risk: "IMDSv1 lets an SSRF bug steal the instance role credentials.",
    recommendation: "Set HttpTokens to required on the instance.",
    cli: "aws ec2 modify-instance-metadata-options --instance-id {name} --http-tokens required",
    fail: "EC2 Instance {name} has IMDSv2 disabled or not required.",
    pass: "EC2 Instance {name} has IMDSv2 enabled and required.",
    compliance: [FSBP, ISO],
  },
  ec2_ebs_volume_encryption: {
    description: "Checks whether the EBS volume is encrypted.",
    risk: "Snapshots and volumes copied out of the account expose the data in clear.",
    recommendation:
      "Enable EBS encryption by default in each region and migrate existing volumes.",
    fail: "EBS Volume {name} is unencrypted.",
    pass: "EBS Volume {name} is encrypted.",
    compliance: [CIS, FSBP, PCI, ISO],
  },
  s3_bucket_secure_transport_policy: {
    description:
      "Checks whether the bucket policy denies requests that are not sent over HTTPS.",
    risk: "Objects can travel unencrypted and be read or changed in transit.",
    recommendation:
      'Add a bucket policy statement that denies s3:* when "aws:SecureTransport" is false.',
    fail: "S3 Bucket {name} allows requests over insecure transport in the bucket policy.",
    pass: "S3 Bucket {name} has a bucket policy to deny requests over insecure transport.",
    compliance: [CIS, FSBP, PCI],
  },
  iam_rotate_access_key_90_days: {
    description: "Checks whether access keys are older than 90 days.",
    risk: "Long-lived keys are more likely to have leaked somewhere.",
    recommendation: "Rotate the key and delete the old one.",
    fail: "User {name} has not rotated access key 1 in over 90 days (214 days).",
    pass: "User {name} does not have access keys older than 90 days.",
    compliance: [CIS, FSBP, PCI, ISO],
  },
  guardduty_is_enabled: {
    description: "Checks whether GuardDuty is enabled in the region.",
    risk: "Malicious activity in the region goes undetected.",
    recommendation:
      "Enable GuardDuty in every region, ideally from a delegated administrator.",
    cli: "aws guardduty create-detector --enable",
    fail: "GuardDuty detector {name} not enabled.",
    pass: "GuardDuty detector {name} enabled.",
    compliance: [FSBP, PCI, ISO, SOC2],
  },
  config_recorder_all_regions_enabled: {
    description: "Checks whether AWS Config records in the region.",
    risk: "Configuration changes in the region leave no history to investigate.",
    recommendation:
      "Enable an AWS Config recorder for all resource types in every region.",
    fail: "AWS Config recorder {name} is disabled.",
    pass: "AWS Config recorder {name} is enabled.",
    compliance: [CIS, FSBP, PCI, SOC2],
  },
  vpc_flow_logs_enabled: {
    description: "Checks whether the VPC has flow logs.",
    risk: "Without flow logs there is no network record for an investigation.",
    recommendation:
      "Enable flow logs on the VPC, at least for rejected traffic.",
    cli: "aws ec2 create-flow-logs --resource-type VPC --resource-ids {name} --traffic-type REJECT --log-destination-type s3 --log-destination arn:aws:s3:::flow-logs",
    fail: "VPC {name} Flow logs are disabled.",
    pass: "VPC {name} Flow logs are enabled.",
    compliance: [CIS, FSBP, PCI, ISO],
  },
  kms_cmk_rotation_enabled: {
    description: "Checks whether automatic rotation is on for the key.",
    risk: "A key that never rotates widens the impact of any key exposure.",
    recommendation: "Enable automatic key rotation.",
    cli: "aws kms enable-key-rotation --key-id {name}",
    fail: "KMS CMK {name} has automatic rotation disabled.",
    pass: "KMS CMK {name} has automatic rotation enabled.",
    compliance: [CIS, FSBP, PCI],
  },
  apigateway_restapi_logging_enabled: {
    description: "Checks whether the API stages have logging enabled.",
    risk: "Requests to the API leave no trace for debugging or investigation.",
    recommendation:
      "Enable CloudWatch execution or access logging on every stage.",
    fail: "API Gateway {name} has stage logging disabled.",
    pass: "API Gateway {name} has stage logging enabled.",
    compliance: [FSBP, PCI],
  },
  sqs_queues_server_side_encryption_enabled: {
    description: "Checks whether the queue uses server-side encryption.",
    risk: "Messages are stored without encryption at rest.",
    recommendation: "Enable SSE-SQS or SSE-KMS on the queue.",
    fail: "SQS queue {name} is not using Server Side Encryption.",
    pass: "SQS queue {name} is using Server Side Encryption.",
    compliance: [FSBP, PCI],
  },
  cloudwatch_log_metric_filter_root_usage: {
    description: "Checks for a metric filter and alarm on root user activity.",
    risk: "Root sign-ins go unnoticed.",
    recommendation:
      "Create a metric filter on the CloudTrail log group for root usage and an alarm on it.",
    fail: "No CloudWatch log groups found with metric filters or alarms associated.",
    pass: "CloudWatch log group {name} found with metric filter and alarms set.",
    compliance: [CIS, PCI],
  },
  ec2_instance_managed_by_ssm: {
    description: "Checks whether Systems Manager manages the instance.",
    risk: "Unmanaged instances miss patching and inventory.",
    recommendation:
      "Install the SSM agent and attach an instance profile with AmazonSSMManagedInstanceCore.",
    fail: "EC2 Instance {name} is not managed by Systems Manager.",
    pass: "EC2 Instance {name} is managed by Systems Manager.",
    compliance: [FSBP, ISO],
  },
  account_maintain_current_contact_details: {
    description: "Reminds you to keep the account contact details current.",
    risk: "AWS cannot reach the right people about security events on the account.",
    recommendation:
      "Review the primary and alternate contacts in the account settings.",
    fail: "Manual check: Login to the AWS Console. Choose your account name on the top right of the window -> My Account -> Contact Information.",
    pass: "Account contact details are current.",
    compliance: [CIS],
  },
};
