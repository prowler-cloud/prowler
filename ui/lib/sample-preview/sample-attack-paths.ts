import type {
  AttackPathQuery,
  AttackPathScan,
  GraphNode,
  GraphRelationship,
  QueryResultAttributes,
} from "@/types/attack-paths";

import { SAMPLE_ACCOUNT, SAMPLE_CHECKS } from "./sample-dataset";

export interface SampleAttackPaths {
  scan: AttackPathScan;
  query: AttackPathQuery;
  result: QueryResultAttributes;
}

const SAMPLE_REGION = "us-east-1";
const SAMPLE_SCAN_COMPLETED_AT = SAMPLE_ACCOUNT.scannedAt;
const SAMPLE_SCAN_STARTED_AT = "2026-10-28T09:04:00Z";

const arn = (service: string, resource: string, region = SAMPLE_REGION) =>
  `arn:aws:${service}:${region}:${SAMPLE_ACCOUNT.uid}:${resource}`;

const resource = (
  id: string,
  label: string,
  properties: GraphNode["properties"],
): GraphNode => ({ id, labels: [label], properties: { id, ...properties } });

// Finding titles and severities come from SAMPLE_CHECKS, like the other pages.
const finding = (id: string, checkId: string): GraphNode => {
  const check = SAMPLE_CHECKS.find((sample) => sample.checkId === checkId);
  return {
    id,
    labels: ["ProwlerFinding"],
    properties: {
      id,
      check_id: checkId,
      check_title: check?.title ?? checkId,
      severity: check?.severity ?? "high",
      status: "FAIL",
    },
  };
};

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
    name: "bastion-ssh",
    groupid: "sg-0a1b2c3d4e5f60718",
    arn: arn("ec2", "security-group/sg-0a1b2c3d4e5f60718"),
    region: SAMPLE_REGION,
  }),
  resource("sample-ec2-bastion", "EC2Instance", {
    name: "bastion-01",
    instanceid: "i-0f1e2d3c4b5a69788",
    arn: arn("ec2", "instance/i-0f1e2d3c4b5a69788"),
    exposed_internet: true,
    publicipaddress: "203.0.113.24",
    region: SAMPLE_REGION,
  }),
  resource("sample-role-admin", "AWSRole", {
    name: "app-admin-role",
    arn: `arn:aws:iam::${SAMPLE_ACCOUNT.uid}:role/app-admin-role`,
  }),
  resource("sample-policy-admin", "AWSPolicy", {
    name: "app-admin-inline",
    arn: `arn:aws:iam::${SAMPLE_ACCOUNT.uid}:policy/app-admin-inline`,
  }),
  resource("sample-s3-exports", "S3Bucket", {
    name: "acme-customer-exports",
    arn: "arn:aws:s3:::acme-customer-exports",
    region: SAMPLE_REGION,
    anonymous_access: true,
  }),
  finding(
    "sample-finding-ssh",
    "ec2_securitygroup_allow_ingress_from_internet_to_tcp_port_22",
  ),
  finding("sample-finding-imdsv2", "ec2_instance_imdsv2_enabled"),
  finding("sample-finding-privesc", "iam_policy_allows_privilege_escalation"),
  finding("sample-finding-public-bucket", "s3_bucket_public_access"),
];

const SAMPLE_RELATIONSHIPS: GraphRelationship[] = [
  rel("sample-r1", "internet", "sample-sg-bastion", "CAN_ACCESS"),
  // A container relation: the graph lays it out as security group -> instance.
  rel("sample-r2", "sample-ec2-bastion", "sample-sg-bastion", "BELONGS_TO"),
  rel(
    "sample-r3",
    "sample-ec2-bastion",
    "sample-role-admin",
    "STS_ASSUMEROLE_ALLOW",
  ),
  rel("sample-r4", "sample-role-admin", "sample-policy-admin", "POLICY"),
  rel("sample-r5", "sample-policy-admin", "sample-s3-exports", "CAN_ACCESS"),
  rel("sample-r6", "sample-sg-bastion", "sample-finding-ssh", "HAS_FINDING"),
  rel(
    "sample-r7",
    "sample-ec2-bastion",
    "sample-finding-imdsv2",
    "HAS_FINDING",
  ),
  rel(
    "sample-r8",
    "sample-role-admin",
    "sample-finding-privesc",
    "HAS_FINDING",
  ),
  rel(
    "sample-r9",
    "sample-s3-exports",
    "sample-finding-public-bucket",
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
