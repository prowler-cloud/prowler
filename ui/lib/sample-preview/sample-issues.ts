import { SEVERITY } from "@/types/components";
import { FINDING_TRIAGE_STATUS } from "@/types/findings-triage";
import {
  type IssueAttributes,
  type IssueResource,
  type IssuesOverviewAttributes,
  LEG_STATE,
  type LegAssessment,
  type LegName,
  VERDICT,
} from "@/types/issues";

import { SAMPLE_ACCOUNT } from "./sample-dataset";

const leg = (
  state: LegAssessment["state"],
  text: string,
  evidence: string[],
): LegAssessment => ({ state, text, evidence });

type SampleIssueSeed = Omit<
  IssueAttributes,
  | "cloud"
  | "account"
  | "triage_status"
  | "notes_count"
  | "inserted_at"
  | "updated_at"
> & { id: string; legs: Record<LegName, LegAssessment> };

// Each issue folds failed findings from SAMPLE_CHECKS along one attack path.
const SAMPLE_ISSUE_SEEDS: SampleIssueSeed[] = [
  {
    id: "sample-issue-public-bucket",
    pattern: "aws_public_bucket",
    title: "Public S3 bucket exposes customer exports to the internet",
    verdict: VERDICT.EXPLOITABLE,
    severity: SEVERITY.CRITICAL,
    outcome: "data_exposure",
    attacker_start: "internet",
    fix: "Turn on S3 Block Public Access for the bucket and remove the public-read grant from its policy.",
    findings_count: 3,
    legs: {
      reachability: leg(
        LEG_STATE.YES,
        "The bucket policy grants s3:GetObject to everyone.",
        ["s3_bucket_public_access"],
      ),
      access: leg(
        LEG_STATE.YES,
        "No credential is needed to list or read objects.",
        ["s3_bucket_public_access"],
      ),
      target: leg(LEG_STATE.YES, "The bucket holds daily customer exports.", [
        "s3_bucket_public_access",
      ]),
      controls: leg(
        LEG_STATE.NO,
        "Encryption in transit is not enforced and no access logging is on.",
        ["s3_bucket_secure_transport_policy"],
      ),
      verification: leg(
        LEG_STATE.YES,
        "An anonymous request returns the object list.",
        [],
      ),
    },
  },
  {
    id: "sample-issue-ssh-instance-role",
    pattern: "aws_exposed_instance_role",
    title: "Internet-facing instance with SSH open carries an admin role",
    verdict: VERDICT.LIKELY,
    severity: SEVERITY.HIGH,
    outcome: "privilege_escalation",
    attacker_start: "internet",
    fix: "Close port 22 to 0.0.0.0/0, require IMDSv2 on the instance and scope its role down to what the workload needs.",
    findings_count: 4,
    legs: {
      reachability: leg(
        LEG_STATE.YES,
        "The security group allows SSH from anywhere.",
        ["ec2_securitygroup_allow_ingress_from_internet_to_tcp_port_22"],
      ),
      access: leg(
        LEG_STATE.PARTIAL,
        "SSH needs a key, but the instance still answers IMDSv1.",
        ["ec2_instance_imdsv2_enabled"],
      ),
      target: leg(
        LEG_STATE.YES,
        "The instance role can pass roles and attach policies.",
        ["iam_policy_allows_privilege_escalation"],
      ),
      controls: leg(LEG_STATE.NO, "GuardDuty is off in this region.", [
        "guardduty_is_enabled",
      ]),
      verification: leg(
        LEG_STATE.UNKNOWN,
        "Not verified against the live instance.",
        [],
      ),
    },
  },
  {
    id: "sample-issue-root-takeover",
    pattern: "aws_root_takeover",
    title: "Root account has no MFA and no alarm on its use",
    verdict: VERDICT.CONDITIONAL,
    severity: SEVERITY.CRITICAL,
    outcome: "privilege_escalation",
    attacker_start: "credential_leak",
    fix: "Enable a hardware MFA device on the root user and add a metric filter and alarm for root sign-ins.",
    findings_count: 2,
    legs: {
      reachability: leg(
        LEG_STATE.YES,
        "The root user can sign in to the console.",
        ["iam_root_mfa_enabled"],
      ),
      access: leg(
        LEG_STATE.PARTIAL,
        "An attacker needs the root password first.",
        ["iam_root_mfa_enabled"],
      ),
      target: leg(
        LEG_STATE.YES,
        "Root controls every resource and billing.",
        [],
      ),
      controls: leg(LEG_STATE.NO, "No alarm fires on root usage.", [
        "cloudwatch_log_metric_filter_root_usage",
      ]),
      verification: leg(LEG_STATE.UNKNOWN, "Not verified.", []),
    },
  },
  {
    id: "sample-issue-lambda-secrets",
    pattern: "aws_secret_store",
    title:
      "Lambda functions keep database credentials in plain environment variables",
    verdict: VERDICT.LIKELY,
    severity: SEVERITY.HIGH,
    outcome: "data_exposure",
    attacker_start: "authenticated_principal",
    fix: "Move the credentials to Secrets Manager and read them at runtime; rotate the exposed ones.",
    findings_count: 2,
    legs: {
      reachability: leg(
        LEG_STATE.YES,
        "Any principal with lambda:GetFunction reads the variables.",
        ["awslambda_function_no_secrets_in_variables"],
      ),
      access: leg(LEG_STATE.YES, "Several roles hold read access to Lambda.", [
        "iam_policy_allows_privilege_escalation",
      ]),
      target: leg(
        LEG_STATE.YES,
        "The credentials open the public RDS instance.",
        ["rds_instance_no_public_access"],
      ),
      controls: leg(
        LEG_STATE.PARTIAL,
        "Access keys rotate, but not every 90 days.",
        ["iam_rotate_access_key_90_days"],
      ),
      verification: leg(LEG_STATE.UNKNOWN, "Not verified.", []),
    },
  },
  {
    id: "sample-issue-unencrypted-volumes",
    pattern: "aws_unencrypted_at_rest",
    title: "EBS volumes and SQS queues store data unencrypted",
    verdict: VERDICT.NOT_EXPLOITABLE,
    severity: SEVERITY.MEDIUM,
    outcome: "",
    attacker_start: "",
    fix: "Turn on EBS encryption by default in each region and enable SSE on the queues.",
    findings_count: 12,
    legs: {
      reachability: leg(
        LEG_STATE.NO,
        "None of the volumes is attached to an exposed instance.",
        ["ec2_ebs_volume_encryption"],
      ),
      access: leg(LEG_STATE.NO, "Reading them needs an existing foothold.", []),
      target: leg(LEG_STATE.PARTIAL, "Some volumes hold application data.", [
        "ec2_ebs_volume_encryption",
      ]),
      controls: leg(
        LEG_STATE.PARTIAL,
        "KMS keys exist but are not used everywhere.",
        ["kms_cmk_rotation_enabled"],
      ),
      verification: leg(LEG_STATE.UNKNOWN, "Not verified.", []),
    },
  },
];

export const SAMPLE_ISSUES: IssueResource[] = SAMPLE_ISSUE_SEEDS.map(
  ({ id, ...attributes }) => ({
    type: "issues",
    id,
    attributes: {
      ...attributes,
      cloud: "aws",
      account: SAMPLE_ACCOUNT.uid,
      triage_status: FINDING_TRIAGE_STATUS.OPEN,
      notes_count: 0,
      inserted_at: SAMPLE_ACCOUNT.scannedAt,
      updated_at: SAMPLE_ACCOUNT.scannedAt,
    },
    relationships: {
      provider: { data: { type: "providers", id: SAMPLE_ACCOUNT.providerId } },
      scan: { data: { type: "scans", id: SAMPLE_ACCOUNT.scanId } },
    },
  }),
);

const countVerdict = (verdict: IssueAttributes["verdict"]) =>
  SAMPLE_ISSUES.filter((issue) => issue.attributes.verdict === verdict).length;

const sumFindings = (issues: IssueResource[]) =>
  issues.reduce((total, issue) => total + issue.attributes.findings_count, 0);

const notExploitable = SAMPLE_ISSUES.filter(
  (issue) => issue.attributes.verdict === VERDICT.NOT_EXPLOITABLE,
);

export const SAMPLE_ISSUES_OVERVIEW: IssuesOverviewAttributes = {
  exploitable: countVerdict(VERDICT.EXPLOITABLE),
  likely: countVerdict(VERDICT.LIKELY),
  conditional: countVerdict(VERDICT.CONDITIONAL),
  not_exploitable: countVerdict(VERDICT.NOT_EXPLOITABLE),
  unknown: countVerdict(VERDICT.UNKNOWN),
  issues: SAMPLE_ISSUES.length,
  findings: sumFindings(SAMPLE_ISSUES),
  actionable: SAMPLE_ISSUES.length - notExploitable.length,
  not_exploitable_findings: sumFindings(notExploitable),
};
