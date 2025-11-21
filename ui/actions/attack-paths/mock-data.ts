/**
 * Mock data for attack paths feature
 * Used for testing and development without backend API
 */

import type {
  AttackPathGraphData,
  AttackPathQuery,
  AttackPathScan,
} from "@/types/attack-paths";

// Mock scans
export const MOCK_ATTACK_PATH_SCANS: AttackPathScan[] = [
  {
    id: "019a8161-4854-79e1-9521-39382d3fdaa1",
    type: "attack-paths-scans",
    attributes: {
      provider_type: "aws",
      provider_alias: "production-account",
      provider_uid: "123456789012",
      state: "completed",
      progress: 100,
      duration: 3456,
      inserted_at: "2024-11-15T10:30:00Z",
      started_at: "2024-11-15T10:30:00Z",
      completed_at: "2024-11-15T11:07:36Z",
    },
    relationships: {
      provider: { data: { type: "provider", id: "aws" } },
      scan: { data: { type: "scan", id: "019a8161" } },
      task: { data: { type: "task", id: "task-001" } },
    },
  },
  {
    id: "019a8162-5965-80f2-0632-40493e4geeb2",
    type: "attack-paths-scans",
    attributes: {
      provider_type: "aws",
      provider_alias: "staging-account",
      provider_uid: "987654321098",
      state: "executing",
      progress: 65,
      duration: 1234,
      inserted_at: "2024-11-15T14:00:00Z",
      started_at: "2024-11-15T14:00:00Z",
      completed_at: null,
    },
    relationships: {
      provider: { data: { type: "provider", id: "aws" } },
      scan: { data: { type: "scan", id: "019a8162" } },
      task: { data: { type: "task", id: "task-002" } },
    },
  },
  {
    id: "019a8163-6a76-91g3-1743-51604f5hffc3",
    type: "attack-paths-scans",
    attributes: {
      provider_type: "azure",
      provider_alias: "azure-dev",
      provider_uid: "subscription-id-123",
      state: "completed",
      progress: 100,
      duration: 2567,
      inserted_at: "2024-11-14T09:15:00Z",
      started_at: "2024-11-14T09:15:00Z",
      completed_at: "2024-11-14T09:57:47Z",
    },
    relationships: {
      provider: { data: { type: "provider", id: "azure" } },
      scan: { data: { type: "scan", id: "019a8163" } },
      task: { data: { type: "task", id: "task-003" } },
    },
  },
  {
    id: "019a8164-7b87-a2h4-2854-62715g6igpd4",
    type: "attack-paths-scans",
    attributes: {
      provider_type: "gcp",
      provider_alias: "gcp-prod",
      provider_uid: "gcp-project-789",
      state: "failed",
      progress: 45,
      duration: 890,
      inserted_at: "2024-11-13T16:20:00Z",
      started_at: "2024-11-13T16:20:00Z",
      completed_at: "2024-11-13T16:34:50Z",
    },
    relationships: {
      provider: { data: { type: "provider", id: "gcp" } },
      scan: { data: { type: "scan", id: "019a8164" } },
      task: { data: { type: "task", id: "task-004" } },
    },
  },
];

// Mock queries
export const MOCK_ATTACK_PATH_QUERIES: AttackPathQuery[] = [
  {
    id: "query-001",
    type: "attack-paths-scans",
    attributes: {
      name: "AWS RDS Instances",
      description: "Find all AWS RDS instances and their access paths",
      provider: "aws",
      parameters: [],
    },
  },
  {
    id: "query-002",
    type: "attack-paths-scans",
    attributes: {
      name: "S3 Anonymous Access Buckets",
      description: "Identify S3 buckets with anonymous access enabled",
      provider: "aws",
      parameters: [
        {
          name: "bucket_prefix",
          label: "Bucket Prefix",
          data_type: "string",
          required: false,
          description: "Filter buckets by name prefix",
        },
      ],
    },
  },
  {
    id: "query-003",
    type: "attack-paths-scans",
    attributes: {
      name: "IAM Role Assume Chain",
      description: "Trace IAM role assumption chains and trust relationships",
      provider: "aws",
      parameters: [
        {
          name: "role_name",
          label: "Role Name",
          data_type: "string",
          required: true,
          description: "Starting IAM role name",
        },
      ],
    },
  },
  {
    id: "query-004",
    type: "attack-paths-scans",
    attributes: {
      name: "EC2 Security Group Paths",
      description: "Find EC2 instances and their security group configurations",
      provider: "aws",
      parameters: [],
    },
  },
  {
    id: "query-005",
    type: "attack-paths-scans",
    attributes: {
      name: "Lambda Function Permissions",
      description: "Analyze Lambda function permissions and invocation paths",
      provider: "aws",
      parameters: [
        {
          name: "function_name",
          label: "Function Name",
          data_type: "string",
          required: false,
          description: "Filter by Lambda function name",
        },
      ],
    },
  },
  {
    id: "query-006",
    type: "attack-paths-scans",
    attributes: {
      name: "Cross-Account Access",
      description: "Find cross-account access configurations and risks",
      provider: "aws",
      parameters: [],
    },
  },
  {
    id: "query-007",
    type: "attack-paths-scans",
    attributes: {
      name: "Prowler Findings to Resources",
      description: "Map security findings to affected resources",
      provider: "aws",
      parameters: [
        {
          name: "severity",
          label: "Severity",
          data_type: "string",
          required: false,
          description:
            "Filter by finding severity (critical, high, medium, low)",
        },
      ],
    },
  },
  {
    id: "query-008",
    type: "attack-paths-scans",
    attributes: {
      name: "VPC Endpoint Access Paths",
      description: "Analyze VPC endpoint configurations and access paths",
      provider: "aws",
      parameters: [],
    },
  },
  {
    id: "query-009",
    type: "attack-paths-scans",
    attributes: {
      name: "KMS Key Access",
      description: "Trace KMS key access and encryption paths",
      provider: "aws",
      parameters: [
        {
          name: "key_id",
          label: "Key ID",
          data_type: "string",
          required: false,
          description: "Specific KMS key ID to analyze",
        },
      ],
    },
  },
  {
    id: "query-010",
    type: "attack-paths-scans",
    attributes: {
      name: "Database Network Access",
      description: "Find databases and their network access configurations",
      provider: "aws",
      parameters: [
        {
          name: "database_type",
          label: "Database Type",
          data_type: "string",
          required: false,
          description: "Filter by database type (RDS, DynamoDB, etc)",
        },
      ],
    },
  },
  {
    id: "query-011",
    type: "attack-paths-scans",
    attributes: {
      name: "Privilege Escalation Paths",
      description: "Identify potential privilege escalation attack paths",
      provider: "aws",
      parameters: [
        {
          name: "starting_principal",
          label: "Starting Principal",
          data_type: "string",
          required: true,
          description: "Initial principal to analyze from",
        },
      ],
    },
  },
];

// Mock query result
export const MOCK_QUERY_RESULT_DATA: AttackPathGraphData = {
  nodes: [
    {
      id: "aws-account-123",
      labels: ["AWSAccount"],
      properties: {
        name: "production-account",
        account_id: "123456789012",
      },
    },
    {
      id: "s3-bucket-data",
      labels: ["S3Bucket"],
      properties: {
        name: "company-data-bucket",
        arn: "arn:aws:s3:::company-data-bucket",
      },
    },
    {
      id: "finding-001",
      labels: ["ProwlerFinding"],
      properties: {
        finding_id: "s3_bucket_public_access_block_enabled",
        severity: "high",
        description: "S3 bucket does not have public access block enabled",
      },
    },
    {
      id: "finding-002",
      labels: ["ProwlerFinding"],
      properties: {
        finding_id: "s3_bucket_server_side_encryption_enabled",
        severity: "medium",
        description: "S3 bucket encryption is not enabled",
      },
    },
    {
      id: "finding-003",
      labels: ["ProwlerFinding"],
      properties: {
        finding_id: "s3_bucket_versioning_enabled",
        severity: "low",
        description: "S3 bucket versioning is not enabled",
      },
    },
    {
      id: "iam-role-lambda",
      labels: ["IAMRole"],
      properties: {
        name: "lambda-execution-role",
        arn: "arn:aws:iam::123456789012:role/lambda-execution-role",
      },
    },
    {
      id: "lambda-function-001",
      labels: ["LambdaFunction"],
      properties: {
        name: "data-processor",
        arn: "arn:aws:lambda:us-east-1:123456789012:function:data-processor",
      },
    },
    {
      id: "ec2-instance-001",
      labels: ["EC2Instance"],
      properties: {
        instance_id: "i-0123456789abcdef0",
        name: "web-server-01",
      },
    },
    {
      id: "security-group-001",
      labels: ["SecurityGroup"],
      properties: {
        group_id: "sg-0123456789abcdef0",
        name: "web-server-sg",
      },
    },
    {
      id: "019a828c-7a03-7c7f-bf2f-9d367470a972",
      labels: ["ProwlerFinding"],
      properties: {
        finding_id: "iam_policy_allows_public_access",
        severity: "critical",
        description: "IAM policy allows unrestricted public access",
      },
    },
    {
      id: "finding-005",
      labels: ["ProwlerFinding"],
      properties: {
        finding_id: "ec2_security_group_allows_all_traffic",
        severity: "high",
        description: "Security group allows all inbound traffic",
      },
    },
    {
      id: "finding-006",
      labels: ["ProwlerFinding"],
      properties: {
        finding_id: "lambda_function_not_versioned",
        severity: "medium",
        description: "Lambda function is not versioned",
      },
    },
    {
      id: "finding-007",
      labels: ["ProwlerFinding"],
      properties: {
        finding_id: "kms_key_rotation_disabled",
        severity: "medium",
        description: "KMS key rotation is disabled",
      },
    },
  ],
  edges: [
    {
      id: "edge-001",
      type: "HAS_FINDING",
      source: "aws-account-123",
      target: "finding-001",
    },
    {
      id: "edge-002",
      type: "CONTAINS",
      source: "aws-account-123",
      target: "s3-bucket-data",
    },
    {
      id: "edge-003",
      type: "HAS_FINDING",
      source: "s3-bucket-data",
      target: "finding-002",
    },
    {
      id: "edge-004",
      type: "HAS_FINDING",
      source: "s3-bucket-data",
      target: "finding-003",
    },
    {
      id: "edge-005",
      type: "ASSUMES",
      source: "lambda-function-001",
      target: "iam-role-lambda",
    },
    {
      id: "edge-006",
      type: "HAS_FINDING",
      source: "iam-role-lambda",
      target: "019a828c-7a03-7c7f-bf2f-9d367470a972",
    },
    {
      id: "edge-007",
      type: "RUNS_IN",
      source: "lambda-function-001",
      target: "aws-account-123",
    },
    {
      id: "edge-008",
      type: "HAS_FINDING",
      source: "lambda-function-001",
      target: "finding-006",
    },
    {
      id: "edge-009",
      type: "ASSOCIATED_WITH",
      source: "ec2-instance-001",
      target: "security-group-001",
    },
    {
      id: "edge-010",
      type: "HAS_FINDING",
      source: "security-group-001",
      target: "finding-005",
    },
    {
      id: "edge-011",
      type: "BELONGS_TO",
      source: "ec2-instance-001",
      target: "aws-account-123",
    },
    {
      id: "edge-012",
      type: "ACCESSES",
      source: "iam-role-lambda",
      target: "s3-bucket-data",
    },
  ],
};
