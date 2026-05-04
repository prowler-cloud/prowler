/**
 * Typed fixture builders for <AttackPathsPage /> browser tests.
 *
 * Each builder returns a self-contained snapshot of the API surface the page
 * exercises: scans list, available queries, and query execution result. The
 * MSW handler factory in the harness turns a fixture into HTTP mocks.
 */

import type {
  AttackPathQuery,
  AttackPathScan,
  GraphNode,
  GraphRelationship,
  QueryResultAttributes,
} from "@/types/attack-paths";

export interface PageFixture {
  scans: AttackPathScan[];
  scanId: string;
  queries: AttackPathQuery[];
  queryId: string;
  queryResult: QueryResultAttributes | null;
  queryError?: { status: number; error: string };
}

const TYPICAL_SCAN_ID = "11111111-1111-4111-8111-111111111111";
const SECOND_SCAN_ID = "22222222-2222-4222-8222-222222222222";

const DEFAULT_QUERY_ID = "aws-public-s3-buckets";

const buildScan = (
  id: string,
  overrides: Partial<AttackPathScan["attributes"]> = {},
): AttackPathScan => ({
  type: "attack-paths-scans",
  id,
  attributes: {
    state: "completed",
    progress: 100,
    graph_data_ready: true,
    provider_alias: `Provider ${id.slice(0, 4)}`,
    provider_type: "aws",
    provider_uid: `123456789${id.slice(0, 3)}`,
    inserted_at: "2026-04-21T10:00:00Z",
    started_at: "2026-04-21T10:00:00Z",
    completed_at: "2026-04-21T10:05:00Z",
    duration: 300,
    ...overrides,
  },
  relationships: {
    provider: { data: { type: "providers", id: `provider-${id}` } },
    scan: { data: { type: "scans", id: `base-scan-${id}` } },
    task: { data: { type: "tasks", id: `task-${id}` } },
  },
});

const buildQuery = (
  id: string,
  name: string,
  overrides: Partial<AttackPathQuery["attributes"]> = {},
): AttackPathQuery => ({
  type: "attack-paths-scans",
  id,
  attributes: {
    name,
    short_description: `Run the ${name} query`,
    description: `Detailed description for ${name}.`,
    provider: "aws",
    parameters: [],
    attribution: null,
    documentation_link: null,
    ...overrides,
  },
});

const buildResourceNode = (
  id: string,
  label: string,
  name: string,
  extraLabels: string[] = [],
): GraphNode => ({
  id,
  labels: [label, ...extraLabels],
  properties: { id, name, arn: `arn:aws:example::${id}` },
});

const buildFindingNode = (
  id: string,
  title: string,
  severity = "high",
): GraphNode => ({
  id,
  labels: ["ProwlerFinding"],
  properties: { id, check_title: title, severity, status: "FAIL" },
});

const buildInternetNode = (): GraphNode => ({
  id: "internet",
  labels: ["Internet"],
  properties: { id: "internet", name: "Internet" },
});

const buildRel = (
  id: string,
  source: string,
  target: string,
  label: string,
): GraphRelationship => ({ id, source, target, label });

export const typical = (): PageFixture => {
  const nodes: GraphNode[] = [
    buildInternetNode(),
    buildResourceNode("ec2-1", "EC2Instance", "api-server-01"),
    buildResourceNode("s3-1", "S3Bucket", "private-data-bucket"),
    buildResourceNode("iam-1", "IAMRole", "AppRole"),
    buildFindingNode("f-1", "S3 bucket is public", "critical"),
    buildFindingNode("f-2", "EC2 exposed to internet", "high"),
  ];
  const relationships: GraphRelationship[] = [
    buildRel("r1", "internet", "ec2-1", "CAN_REACH"),
    buildRel("r2", "ec2-1", "s3-1", "CAN_ACCESS"),
    buildRel("r3", "ec2-1", "iam-1", "ASSUMES"),
    buildRel("r4", "s3-1", "f-1", "HAS_FINDING"),
    buildRel("r5", "ec2-1", "f-2", "HAS_FINDING"),
  ];
  return {
    scans: [buildScan(TYPICAL_SCAN_ID), buildScan(SECOND_SCAN_ID)],
    scanId: TYPICAL_SCAN_ID,
    queries: [
      buildQuery(DEFAULT_QUERY_ID, "Public S3 buckets"),
      buildQuery("aws-open-security-groups", "Open security groups"),
    ],
    queryId: DEFAULT_QUERY_ID,
    queryResult: { nodes, relationships },
  };
};

export const emptyScans = (): PageFixture => ({
  scans: [],
  scanId: TYPICAL_SCAN_ID,
  queries: [],
  queryId: DEFAULT_QUERY_ID,
  queryResult: null,
});

export const emptyGraph = (): PageFixture => ({
  scans: [buildScan(TYPICAL_SCAN_ID)],
  scanId: TYPICAL_SCAN_ID,
  queries: [buildQuery(DEFAULT_QUERY_ID, "Public S3 buckets")],
  queryId: DEFAULT_QUERY_ID,
  queryResult: null,
  queryError: { status: 404, error: "No data found" },
});

export const singleNode = (): PageFixture => ({
  scans: [buildScan(TYPICAL_SCAN_ID)],
  scanId: TYPICAL_SCAN_ID,
  queries: [buildQuery(DEFAULT_QUERY_ID, "Public S3 buckets")],
  queryId: DEFAULT_QUERY_ID,
  queryResult: {
    nodes: [buildResourceNode("only-1", "S3Bucket", "solitary-bucket")],
    relationships: [],
  },
});

export const findingsOnly = (): PageFixture => ({
  scans: [buildScan(TYPICAL_SCAN_ID)],
  scanId: TYPICAL_SCAN_ID,
  queries: [buildQuery(DEFAULT_QUERY_ID, "Findings only")],
  queryId: DEFAULT_QUERY_ID,
  queryResult: {
    nodes: [
      buildFindingNode("f-1", "Finding A", "critical"),
      buildFindingNode("f-2", "Finding B", "high"),
      buildFindingNode("f-3", "Finding C", "medium"),
    ],
    relationships: [],
  },
});

export const resourcesOnly = (): PageFixture => ({
  scans: [buildScan(TYPICAL_SCAN_ID)],
  scanId: TYPICAL_SCAN_ID,
  queries: [buildQuery(DEFAULT_QUERY_ID, "Resources only")],
  queryId: DEFAULT_QUERY_ID,
  queryResult: {
    nodes: [
      buildResourceNode("ec2-1", "EC2Instance", "web-1"),
      buildResourceNode("ec2-2", "EC2Instance", "web-2"),
      buildResourceNode("s3-1", "S3Bucket", "logs"),
    ],
    relationships: [
      buildRel("r1", "ec2-1", "s3-1", "CAN_ACCESS"),
      buildRel("r2", "ec2-2", "s3-1", "CAN_ACCESS"),
    ],
  },
});

export const disconnected = (): PageFixture => ({
  scans: [buildScan(TYPICAL_SCAN_ID)],
  scanId: TYPICAL_SCAN_ID,
  queries: [buildQuery(DEFAULT_QUERY_ID, "Disconnected components")],
  queryId: DEFAULT_QUERY_ID,
  queryResult: {
    nodes: [
      buildResourceNode("a-1", "EC2Instance", "alpha-ec2"),
      buildResourceNode("a-2", "S3Bucket", "alpha-s3"),
      buildResourceNode("b-1", "EC2Instance", "beta-ec2"),
      buildResourceNode("b-2", "S3Bucket", "beta-s3"),
    ],
    relationships: [
      buildRel("r1", "a-1", "a-2", "CAN_ACCESS"),
      buildRel("r2", "b-1", "b-2", "CAN_ACCESS"),
    ],
  },
});

export const large = (count = 200): PageFixture => {
  const nodes: GraphNode[] = [];
  const relationships: GraphRelationship[] = [];
  for (let i = 0; i < count; i++) {
    const id = `n-${i}`;
    if (i % 5 === 0) {
      nodes.push(buildFindingNode(id, `Finding ${i}`, "high"));
    } else {
      nodes.push(buildResourceNode(id, "EC2Instance", `instance-${i}`));
    }
    if (i > 0) {
      relationships.push(buildRel(`r-${i}`, `n-${i - 1}`, id, "CAN_REACH"));
    }
  }
  return {
    scans: [buildScan(TYPICAL_SCAN_ID)],
    scanId: TYPICAL_SCAN_ID,
    queries: [buildQuery(DEFAULT_QUERY_ID, "Large graph")],
    queryId: DEFAULT_QUERY_ID,
    queryResult: { nodes, relationships },
  };
};

export const edgeCases = (): PageFixture => {
  const longLabel =
    "a very long resource name that should be truncated ".repeat(4);
  const nodes: GraphNode[] = [
    buildResourceNode("self-1", "EC2Instance", "self-loop"),
    buildResourceNode("cy-1", "EC2Instance", "cycle-a"),
    buildResourceNode("cy-2", "EC2Instance", "cycle-b"),
    buildResourceNode("long-1", "EC2Instance", longLabel),
    buildResourceNode("emoji-1", "S3Bucket", "🔒-secure-bucket-日本語"),
    buildResourceNode("dup-a", "EC2Instance", "dup-source"),
    buildResourceNode("dup-b", "S3Bucket", "dup-target"),
  ];
  const relationships: GraphRelationship[] = [
    buildRel("self-edge", "self-1", "self-1", "REFERS_TO"),
    buildRel("cy-a", "cy-1", "cy-2", "CAN_REACH"),
    buildRel("cy-b", "cy-2", "cy-1", "CAN_REACH"),
    buildRel("dup-1", "dup-a", "dup-b", "CAN_ACCESS"),
    buildRel("dup-2", "dup-a", "dup-b", "CAN_ACCESS"),
  ];
  return {
    scans: [buildScan(TYPICAL_SCAN_ID)],
    scanId: TYPICAL_SCAN_ID,
    queries: [buildQuery(DEFAULT_QUERY_ID, "Edge cases")],
    queryId: DEFAULT_QUERY_ID,
    queryResult: { nodes, relationships },
  };
};

export const fixtures = {
  typical,
  emptyScans,
  emptyGraph,
  singleNode,
  findingsOnly,
  resourcesOnly,
  disconnected,
  large,
  edgeCases,
};
