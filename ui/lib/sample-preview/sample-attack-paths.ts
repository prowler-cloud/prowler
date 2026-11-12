import type {
  AttackPathQuery,
  AttackPathScan,
  GraphNode,
  GraphRelationship,
  QueryResultAttributes,
} from "@/types/attack-paths";

import { SAMPLE_ACCOUNT } from "./sample-dataset";
import { failedSampleFindings, type SampleFinding } from "./sample-records";

export interface SampleAttackPaths {
  scan: AttackPathScan;
  query: AttackPathQuery;
  result: QueryResultAttributes;
}

const SAMPLE_SCAN_COMPLETED_AT = SAMPLE_ACCOUNT.scannedAt;
const SAMPLE_SCAN_STARTED_AT = "2026-10-28T09:04:00Z";

const resource = (
  id: string,
  label: string,
  properties: GraphNode["properties"],
): GraphNode => ({ id, labels: [label], properties: { id, ...properties } });

// Each finding node is a sample record, so the finding drawer opens it.
const failingRecord = (checkId: string) => {
  const [record] = failedSampleFindings(checkId);
  if (!record) throw new Error(`No failing sample finding for ${checkId}`);
  return record;
};

const SSH_FINDING = failingRecord(
  "ec2_securitygroup_allow_ingress_from_internet_to_tcp_port_22",
);
const IMDSV2_FINDING = failingRecord("ec2_instance_imdsv2_enabled");
const PRIVESC_FINDING = failingRecord("iam_policy_allows_privilege_escalation");
const PUBLIC_BUCKET_FINDING = failingRecord("s3_bucket_public_access");

const finding = (record: SampleFinding): GraphNode => ({
  id: record.id,
  labels: ["ProwlerFinding"],
  properties: {
    id: record.id,
    check_id: record.check.checkId,
    check_title: record.check.title,
    severity: record.check.severity,
    status: "FAIL",
  },
});

// Resource nodes reuse the records' names and ARNs, so graph and drawer agree.
const recordProperties = ({ resource }: SampleFinding) => ({
  name: resource.name,
  arn: resource.uid,
  region: resource.region,
});

const rel = (
  id: string,
  source: string,
  target: string,
  label: string,
): GraphRelationship => ({ id, source, target, label });

// Internet -> SSH-open security group -> EC2 -> admin role -> policy -> bucket.
const SAMPLE_NODES: GraphNode[] = [
  {
    id: "internet",
    labels: ["Internet"],
    properties: { id: "internet", name: "Internet" },
  },
  resource("sample-sg-bastion", "EC2SecurityGroup", {
    ...recordProperties(SSH_FINDING),
    groupid: SSH_FINDING.resource.name,
  }),
  resource("sample-ec2-bastion", "EC2Instance", {
    ...recordProperties(IMDSV2_FINDING),
    instanceid: IMDSV2_FINDING.resource.name,
    exposed_internet: true,
    publicipaddress: "203.0.113.24",
  }),
  resource("sample-role-admin", "AWSRole", {
    name: "app-admin-role",
    arn: `arn:aws:iam::${SAMPLE_ACCOUNT.uid}:role/app-admin-role`,
  }),
  resource("sample-policy-admin", "AWSPolicy", {
    name: PRIVESC_FINDING.resource.name,
    arn: PRIVESC_FINDING.resource.uid,
  }),
  resource("sample-s3-exports", "S3Bucket", {
    ...recordProperties(PUBLIC_BUCKET_FINDING),
    anonymous_access: true,
  }),
  finding(SSH_FINDING),
  finding(IMDSV2_FINDING),
  finding(PRIVESC_FINDING),
  finding(PUBLIC_BUCKET_FINDING),
];

const SAMPLE_RELATIONSHIPS: GraphRelationship[] = [
  rel("sample-r1", "internet", "sample-sg-bastion", "CAN_ACCESS"),
  // Directed security group -> instance, so the focused path keeps the entry.
  rel("sample-r2", "sample-sg-bastion", "sample-ec2-bastion", "CAN_ACCESS"),
  rel(
    "sample-r3",
    "sample-ec2-bastion",
    "sample-role-admin",
    "STS_ASSUMEROLE_ALLOW",
  ),
  rel("sample-r4", "sample-role-admin", "sample-policy-admin", "POLICY"),
  rel("sample-r5", "sample-policy-admin", "sample-s3-exports", "CAN_ACCESS"),
  rel("sample-r6", "sample-sg-bastion", SSH_FINDING.id, "HAS_FINDING"),
  rel("sample-r7", "sample-ec2-bastion", IMDSV2_FINDING.id, "HAS_FINDING"),
  // The record's failing resource is the policy the role carries.
  rel("sample-r8", "sample-policy-admin", PRIVESC_FINDING.id, "HAS_FINDING"),
  rel(
    "sample-r9",
    "sample-s3-exports",
    PUBLIC_BUCKET_FINDING.id,
    "HAS_FINDING",
  ),
];

export const SAMPLE_ATTACK_PATHS: SampleAttackPaths = {
  scan: {
    type: "attack-paths-scans",
    id: "sample-attack-paths-scan",
    attributes: {
      state: "completed",
      progress: 100,
      graph_data_ready: true,
      provider_alias: SAMPLE_ACCOUNT.alias,
      provider_type: "aws",
      provider_uid: SAMPLE_ACCOUNT.uid,
      inserted_at: SAMPLE_SCAN_STARTED_AT,
      started_at: SAMPLE_SCAN_STARTED_AT,
      completed_at: SAMPLE_SCAN_COMPLETED_AT,
      duration: 480,
    },
    relationships: {
      provider: { data: { type: "providers", id: SAMPLE_ACCOUNT.providerId } },
      scan: { data: { type: "scans", id: SAMPLE_ACCOUNT.scanId } },
      task: { data: { type: "tasks", id: "sample-task" } },
    },
  },
  // Mirrors the API's query of the same id, without its tag parameters.
  query: {
    type: "attack-paths-scans",
    id: "aws-internet-exposed-ec2-sensitive-s3-access",
    attributes: {
      name: "Internet-Exposed EC2 with Sensitive S3 Access",
      short_description:
        "Find SSH-exposed EC2 instances that can assume roles to read sensitive S3 buckets.",
      description:
        "Detect EC2 instances with SSH exposed to the internet that can assume higher-privileged roles to read sensitive S3 buckets.",
      provider: "aws",
      parameters: [],
      attribution: null,
      documentation_link: null,
      outcome: { kind: "public_exposure", label: "Public exposure" },
    },
  },
  result: { nodes: SAMPLE_NODES, relationships: SAMPLE_RELATIONSHIPS },
};
