/**
 * Mock data for Attack Paths feature development
 * Based on actual API response structure
 */

import type {
  AttackPathQueriesResponse,
  AttackPathQueryResult,
  AttackPathScansResponse,
} from "@/types/attack-paths";

export const mockScansResponse: AttackPathScansResponse = {
  data: [
    {
      type: "attack-paths-scans",
      id: "019a8161-4854-79e1-9521-39382d3fdaa1",
      attributes: {
        state: "completed",
        progress: 100,
        inserted_at: "2025-11-14T08:00:27.733006Z",
        started_at: "2025-11-14T08:00:27.732448Z",
        completed_at: "2025-11-14T08:57:25.645282Z",
        duration: 3417,
      },
      relationships: {
        provider: {
          data: {
            type: "providers",
            id: "d9339f56-aa32-4ec1-af79-6d58a8ad4ff8",
          },
        },
        scan: {
          data: {
            type: "scans",
            id: "019a8151-2b2c-76a8-85a4-d58671d7cf53",
          },
        },
        task: {
          data: {
            type: "tasks",
            id: "2dbd8600-7699-45f6-b614-ab4800131b61",
          },
        },
      },
    },
    {
      type: "attack-paths-scans",
      id: "019a81c1-4e7e-737e-b69a-2a3c5aa5a4b3",
      attributes: {
        state: "executing",
        progress: 45,
        inserted_at: "2025-11-14T09:45:20.767123Z",
        started_at: "2025-11-14T09:45:20.766438Z",
        completed_at: null,
        duration: null,
      },
      relationships: {
        provider: {
          data: {
            type: "providers",
            id: "1fab1afa-a8a2-41aa-bdfd-a2a53a8f1e64",
          },
        },
        scan: {
          data: {
            type: "scans",
            id: "019a81b5-208c-747b-b985-c3de5fa56f60",
          },
        },
        task: {
          data: {
            type: "tasks",
            id: "342b453f-934f-4c70-b92c-02885da0eb37",
          },
        },
      },
    },
  ],
  links: {
    first: "http://localhost:8080/api/v1/attack-paths-scans?page%5Bnumber%5D=1",
    last: "http://localhost:8080/api/v1/attack-paths-scans?page%5Bnumber%5D=1",
    next: null,
    prev: null,
  },
};

export const mockQueriesResponse: AttackPathQueriesResponse = {
  data: [
    {
      type: "attack-paths-scans",
      id: "aws-s3-buckets",
      attributes: {
        name: "S3 buckets",
        description: "Explore all S3 buckets in the AWS account",
        provider: "aws",
        parameters: [],
      },
    },
    {
      type: "attack-paths-scans",
      id: "aws-ec2-instance-security-groups",
      attributes: {
        name: "EC2 instance security group exposure",
        description:
          "Explore the security groups and network interfaces attached to a specific EC2 instance to understand its exposure surface.",
        provider: "aws",
        parameters: [
          {
            name: "instance_id",
            label: "EC2 instance ID",
            data_type: "string",
            description:
              "Full identifier of the EC2 instance, e.g. i-0abc123456789def0.",
            placeholder: "i-0abc123456789def0",
          },
          {
            name: "security_group_id",
            label: "Security Group ID",
            data_type: "string",
            description:
              "Full identifier of the security group, e.g. sg-0abc123456789def0.",
            placeholder: "sg-0abc123456789def0",
          },
        ],
      },
    },
    {
      type: "attack-paths-scans",
      id: "aws-s3-bucket-access",
      attributes: {
        name: "S3 bucket access graph",
        description:
          "Show identities that have direct relationships with a given S3 bucket.",
        provider: "aws",
        parameters: [
          {
            name: "bucket_name",
            label: "S3 bucket name",
            data_type: "string",
            description: "Case-sensitive bucket name, e.g. production-logs.",
            placeholder: "production-logs",
          },
        ],
      },
    },
  ],
};

export const mockGraphQueryResult: AttackPathQueryResult = {
  data: {
    type: "attack-paths-query-run-request",
    id: null,
    attributes: {
      nodes: [
        {
          id: "4:ff927085-8a86-4627-b9d8-a211514c655f:0",
          labels: ["AWSAccount"],
          properties: {
            firstseen: 1763107232399,
            _module_version: "0.117.0",
            name: "prowler-dev",
            inscope: true,
            lastupdated: 1763113520,
            id: "106908755756",
            _module_name: "cartography:aws",
          },
        },
        {
          id: "4:ff927085-8a86-4627-b9d8-a211514c655f:1354",
          labels: ["S3Bucket"],
          properties: {
            bucket_key_enabled: true,
            creationdate: "2025-07-21 10:41:15+00:00",
            ignore_public_acls: true,
            anonymous_access: false,
            firstseen: 1763107338237,
            block_public_policy: true,
            logging_enabled: false,
            block_public_acls: true,
            name: "adri-scans",
            lastupdated: 1763107227,
            object_ownership: "BucketOwnerEnforced",
            encryption_algorithm: "AES256",
            default_encryption: true,
            id: "adri-scans",
            arn: "arn:aws:s3:::adri-scans",
            region: "eu-west-1",
            restrict_public_buckets: true,
          },
        },
        {
          id: "4:ff927085-8a86-4627-b9d8-a211514c655f:1355",
          labels: ["S3Bucket"],
          properties: {
            bucket_key_enabled: false,
            creationdate: "2025-06-15 14:30:22+00:00",
            ignore_public_acls: false,
            anonymous_access: true,
            firstseen: 1763107338300,
            block_public_policy: false,
            logging_enabled: true,
            block_public_acls: false,
            anonymous_actions: "s3:GetObject",
            name: "public-assets",
            lastupdated: 1763107228,
            object_ownership: "ObjectWriter",
            encryption_algorithm: "aws:kms",
            default_encryption: true,
            id: "public-assets",
            arn: "arn:aws:s3:::public-assets",
            region: "us-east-1",
            restrict_public_buckets: false,
          },
        },
        {
          id: "4:ff927085-8a86-4627-b9d8-a211514c655f:2001",
          labels: ["EC2Instance"],
          properties: {
            instanceid: "i-0123456789abcdef0",
            name: "web-server-1",
            state: "running",
            instancetype: "t3.medium",
            launchtime: "2025-07-10T12:00:00Z",
            region: "us-east-1",
            firstseen: 1763107400000,
            lastupdated: 1763113500000,
          },
        },
        {
          id: "4:ff927085-8a86-4627-b9d8-a211514c655f:3001",
          labels: ["IAMRole"],
          properties: {
            rolename: "ec2-s3-access-role",
            arn: "arn:aws:iam::106908755756:role/ec2-s3-access-role",
            createdate: "2025-05-20T08:15:00Z",
            firstseen: 1763107450000,
            lastupdated: 1763113550000,
          },
        },
        {
          id: "4:ff927085-8a86-4627-b9d8-a211514c655f:4001",
          labels: ["ProwlerFinding"],
          properties: {
            finding_id: "finding-s3-public-access",
            check_id: "s3_bucket_public_access_block",
            severity: "high",
            status: "FAIL",
            resource_id: "arn:aws:s3:::public-assets",
            firstseen: 1763107500000,
            lastupdated: 1763113600000,
          },
        },
      ],
      edges: [
        {
          id: "edge-1",
          type: "HAS",
          source: "4:ff927085-8a86-4627-b9d8-a211514c655f:0",
          target: "4:ff927085-8a86-4627-b9d8-a211514c655f:1354",
          properties: {},
        },
        {
          id: "edge-2",
          type: "HAS",
          source: "4:ff927085-8a86-4627-b9d8-a211514c655f:0",
          target: "4:ff927085-8a86-4627-b9d8-a211514c655f:1355",
          properties: {},
        },
        {
          id: "edge-3",
          type: "HAS",
          source: "4:ff927085-8a86-4627-b9d8-a211514c655f:0",
          target: "4:ff927085-8a86-4627-b9d8-a211514c655f:2001",
          properties: {},
        },
        {
          id: "edge-4",
          type: "ASSUMES",
          source: "4:ff927085-8a86-4627-b9d8-a211514c655f:2001",
          target: "4:ff927085-8a86-4627-b9d8-a211514c655f:3001",
          properties: {},
        },
        {
          id: "edge-5",
          type: "ALLOWS_ACCESS",
          source: "4:ff927085-8a86-4627-b9d8-a211514c655f:3001",
          target: "4:ff927085-8a86-4627-b9d8-a211514c655f:1355",
          properties: {},
        },
        {
          id: "edge-6",
          type: "HAS_FINDING",
          source: "4:ff927085-8a86-4627-b9d8-a211514c655f:1355",
          target: "4:ff927085-8a86-4627-b9d8-a211514c655f:4001",
          properties: {},
        },
      ],
    },
  },
};
