import {
  AlertTriangle,
  Bot,
  Braces,
  CircleAlert,
  FileKey2,
  Globe2,
  Info,
  KeyRound,
  Route,
  Server,
  Shield,
  ShieldCheck,
  Siren,
  Tags,
  UserCog,
  Users,
  Waypoints,
} from "lucide-react";
import { describe, expect, it } from "vitest";

import {
  AWSProviderBadge,
  AzureProviderBadge,
  GCPProviderBadge,
  KS8ProviderBadge,
} from "@/components/icons/providers-badge";
import {
  AmazonEC2Icon,
  AmazonRDSIcon,
  AmazonS3Icon,
  AmazonVPCIcon,
  AWSIAMIcon,
  AWSLambdaIcon,
} from "@/components/icons/services/IconServices";
import type { GraphNode } from "@/types/attack-paths";

import { NODE_CATEGORY, resolveNodeVisual } from "./node-visuals";

const buildNode = (labels: string[], properties = {}): GraphNode => ({
  id: labels[0] ?? "unknown-node",
  labels,
  properties,
});

describe("resolveNodeVisual", () => {
  describe("exact label mappings", () => {
    it("should resolve AWSAccount nodes to account metadata", () => {
      // Given
      const node = buildNode(["AWSAccount"], { name: "Production" });

      // When
      const visual = resolveNodeVisual(node);

      // Then
      expect(visual).toMatchObject({
        category: NODE_CATEGORY.ACCOUNT,
        displayName: "Production",
        description: "AWS Account",
        fallbackUsed: false,
      });
      expect(visual.Icon).toBe(AWSProviderBadge);
    });

    it("should resolve cloud provider root nodes to provider badges", () => {
      // Given
      const providerNodes = [
        {
          label: "AzureTenant",
          description: "Azure Tenant",
          Icon: AzureProviderBadge,
        },
        {
          label: "GCPProject",
          description: "Google Cloud Project",
          Icon: GCPProviderBadge,
        },
        {
          label: "KubernetesCluster",
          description: "Kubernetes Cluster",
          Icon: KS8ProviderBadge,
        },
      ];

      for (const providerNode of providerNodes) {
        // When
        const visual = resolveNodeVisual(
          buildNode([providerNode.label], { name: providerNode.description }),
        );

        // Then
        expect(visual).toMatchObject({
          category: NODE_CATEGORY.ACCOUNT,
          displayName: providerNode.description,
          description: providerNode.description,
          fallbackUsed: false,
        });
        expect(visual.Icon).toBe(providerNode.Icon);
      }
    });

    it("should resolve S3Bucket nodes to storage metadata", () => {
      // Given
      const node = buildNode(["S3Bucket"], { name: "public-assets" });

      // When
      const visual = resolveNodeVisual(node);

      // Then
      expect(visual).toMatchObject({
        category: NODE_CATEGORY.STORAGE,
        displayName: "public-assets",
        description: "S3 Bucket",
        fallbackUsed: false,
      });
      expect(visual.Icon).toBe(AmazonS3Icon);
    });

    it.each([
      ["AWSAccount", NODE_CATEGORY.ACCOUNT, "AWS Account", AWSProviderBadge],
      ["S3Bucket", NODE_CATEGORY.STORAGE, "S3 Bucket", AmazonS3Icon],
      ["S3", NODE_CATEGORY.STORAGE, "S3", AmazonS3Icon],
      ["VPC", NODE_CATEGORY.NETWORK, "VPC", AmazonVPCIcon],
      ["Subnet", NODE_CATEGORY.NETWORK, "Subnet", Waypoints],
      ["SecurityGroup", NODE_CATEGORY.NETWORK, "Security Group", Shield],
      ["InternetGateway", NODE_CATEGORY.NETWORK, "Internet Gateway", Route],
      ["DefaultGateway", NODE_CATEGORY.NETWORK, "Default Gateway", Route],
      ["EC2Instance", NODE_CATEGORY.COMPUTE, "EC2 Instance", AmazonEC2Icon],
      [
        "VirtualMachine",
        NODE_CATEGORY.COMPUTE,
        "Virtual Machine",
        AmazonEC2Icon,
      ],
      ["Compute", NODE_CATEGORY.COMPUTE, "Compute", Server],
      ["NIC", NODE_CATEGORY.COMPUTE, "NIC", Server],
      ["IAMUser", NODE_CATEGORY.IDENTITY, "IAM User", AWSIAMIcon],
      ["IAMRole", NODE_CATEGORY.IDENTITY, "IAM Role", AWSIAMIcon],
      ["ServiceAccount", NODE_CATEGORY.IDENTITY, "Service Account", Bot],
      ["AccessKey", NODE_CATEGORY.SECRET, "Access Key", KeyRound],
      ["Secret", NODE_CATEGORY.SECRET, "Secret", KeyRound],
    ] as const)(
      "should map %s to %s with the expected icon",
      (label, category, description, Icon) => {
        // Given
        const node = buildNode([label]);

        // When
        const visual = resolveNodeVisual(node);

        // Then
        expect(visual).toMatchObject({
          category,
          description,
          fallbackUsed: false,
        });
        expect(visual.Icon).toBe(Icon);
      },
    );

    it("should resolve VPC nodes to network metadata", () => {
      // Given
      const node = buildNode(["VPC"], { name: "main-vpc" });

      // When
      const visual = resolveNodeVisual(node);

      // Then
      expect(visual).toMatchObject({
        category: NODE_CATEGORY.NETWORK,
        displayName: "main-vpc",
        description: "VPC",
        fallbackUsed: false,
      });
      expect(visual.Icon).toBe(AmazonVPCIcon);
    });

    it("should resolve ProwlerFinding nodes to finding metadata", () => {
      // Given
      const node = buildNode(["ProwlerFinding"], {
        check_title: "S3 bucket is public",
      });

      // When
      const visual = resolveNodeVisual(node);

      // Then
      expect(visual).toMatchObject({
        category: NODE_CATEGORY.FINDING,
        displayName: "S3 bucket is public",
        description: "Prowler Finding",
        fallbackUsed: false,
      });
    });

    it("should resolve cloud-provider finding resources as non-finding nodes", () => {
      // Given
      const guardDutyNode = buildNode(["GuardDutyFinding"], {
        title: "Port probe",
        severity: "high",
      });
      const inspectorNode = buildNode(["AWSInspectorFinding"], {
        title: "Package vulnerability",
        severity: "high",
      });

      // When
      const guardDutyVisual = resolveNodeVisual(guardDutyNode);
      const inspectorVisual = resolveNodeVisual(inspectorNode);

      // Then
      expect(guardDutyVisual.category).not.toBe(NODE_CATEGORY.FINDING);
      expect(guardDutyVisual.description).toBe("Guard Duty Finding");
      expect(inspectorVisual.category).not.toBe(NODE_CATEGORY.FINDING);
      expect(inspectorVisual.description).toBe("Aws Inspector Finding");
    });

    it("should resolve finding icons from severity", () => {
      // Given
      const findingNodes = [
        { severity: "critical", Icon: Siren },
        { severity: "high", Icon: AlertTriangle },
        { severity: "medium", Icon: CircleAlert },
        { severity: "low", Icon: Info },
        { severity: "informational", Icon: Info },
      ];

      for (const findingNode of findingNodes) {
        // When
        const visual = resolveNodeVisual(
          buildNode(["ProwlerFinding"], {
            check_title: `${findingNode.severity} finding`,
            severity: findingNode.severity,
          }),
        );

        // Then
        expect(visual).toMatchObject({
          category: NODE_CATEGORY.FINDING,
          description: "Prowler Finding",
          fallbackUsed: false,
        });
        expect(visual.Icon).toBe(findingNode.Icon);
      }
    });

    it("should use the generic alert icon when finding severity is unknown", () => {
      // Given
      const node = buildNode(["ProwlerFinding"], {
        check_title: "Unknown risk",
        severity: "unknown",
      });

      // When
      const visual = resolveNodeVisual(node);

      // Then
      expect(visual.Icon).toBe(AlertTriangle);
    });

    it("should resolve Internet nodes to internet metadata", () => {
      // Given
      const node = buildNode(["Internet"]);

      // When
      const visual = resolveNodeVisual(node);

      // Then
      expect(visual).toMatchObject({
        category: NODE_CATEGORY.INTERNET,
        displayName: "Internet",
        description: "Internet",
        fallbackUsed: false,
      });
    });
  });

  describe("alias and normalized mappings", () => {
    it("should resolve IAMUser nodes to identity metadata with the AWS IAM icon", () => {
      // Given
      const node = buildNode(["IAMUser"], { name: "alice" });

      // When
      const visual = resolveNodeVisual(node);

      // Then
      expect(visual).toMatchObject({
        category: NODE_CATEGORY.IDENTITY,
        displayName: "alice",
        description: "IAM User",
        fallbackUsed: false,
      });
      expect(visual.Icon).toBe(AWSIAMIcon);
    });

    it("should resolve case-insensitive AccessKey labels to secret metadata", () => {
      // Given
      const node = buildNode(["access_key"], { id: "AKIA123" });

      // When
      const visual = resolveNodeVisual(node);

      // Then
      expect(visual).toMatchObject({
        category: NODE_CATEGORY.SECRET,
        displayName: "AKIA123",
        description: "Access Key",
        fallbackUsed: false,
      });
    });

    it("should resolve AWS identity and policy labels to distinct icons", () => {
      // Given
      const identityNodes = [
        {
          label: "AWSUser",
          description: "AWS User",
          Icon: UserCog,
        },
        {
          label: "AWSManagedPolicy",
          description: "AWS Managed Policy",
          Icon: FileKey2,
        },
        {
          label: "AWSPolicyStatement",
          description: "AWS Policy Statement",
          Icon: Braces,
        },
        {
          label: "PermissionRole",
          description: "Permission Role",
          Icon: ShieldCheck,
        },
      ];

      for (const identityNode of identityNodes) {
        // When
        const visual = resolveNodeVisual(
          buildNode([identityNode.label], { name: identityNode.description }),
        );

        // Then
        expect(visual).toMatchObject({
          category: NODE_CATEGORY.IDENTITY,
          displayName: identityNode.description,
          description: identityNode.description,
          fallbackUsed: false,
        });
        expect(visual.Icon).toBe(identityNode.Icon);
      }
    });

    it("should resolve all AWS labels used by predefined Attack Paths queries", () => {
      // Given
      const awsQueryNodes = [
        {
          label: "AWSTag",
          category: NODE_CATEGORY.MISC,
          description: "AWS Tag",
          Icon: Tags,
        },
        {
          label: "EC2SecurityGroup",
          category: NODE_CATEGORY.NETWORK,
          description: "EC2 Security Group",
          Icon: Shield,
        },
        {
          label: "IpPermissionInbound",
          category: NODE_CATEGORY.NETWORK,
          description: "Inbound IP Permission",
          Icon: Shield,
        },
        {
          label: "IpRange",
          category: NODE_CATEGORY.NETWORK,
          description: "IP Range",
          Icon: Globe2,
        },
        {
          label: "AWSPrincipal",
          category: NODE_CATEGORY.IDENTITY,
          description: "AWS Principal",
          Icon: ShieldCheck,
        },
        {
          label: "AWSGroup",
          category: NODE_CATEGORY.IDENTITY,
          description: "AWS Group",
          Icon: Users,
        },
        {
          label: "RDSInstance",
          category: NODE_CATEGORY.STORAGE,
          description: "RDS Instance",
          Icon: AmazonRDSIcon,
        },
        {
          label: "LoadBalancer",
          category: NODE_CATEGORY.NETWORK,
          description: "Load Balancer",
          Icon: Route,
        },
        {
          label: "ELBListener",
          category: NODE_CATEGORY.NETWORK,
          description: "ELB Listener",
          Icon: Route,
        },
        {
          label: "LoadBalancerV2",
          category: NODE_CATEGORY.NETWORK,
          description: "Load Balancer V2",
          Icon: Route,
        },
        {
          label: "ELBV2Listener",
          category: NODE_CATEGORY.NETWORK,
          description: "ELB V2 Listener",
          Icon: Route,
        },
        {
          label: "ElasticIPAddress",
          category: NODE_CATEGORY.NETWORK,
          description: "Elastic IP Address",
          Icon: Globe2,
        },
        {
          label: "EC2PrivateIp",
          category: NODE_CATEGORY.NETWORK,
          description: "EC2 Private IP",
          Icon: Waypoints,
        },
        {
          label: "NetworkInterface",
          category: NODE_CATEGORY.NETWORK,
          description: "Network Interface",
          Icon: Waypoints,
        },
        {
          label: "LaunchTemplate",
          category: NODE_CATEGORY.COMPUTE,
          description: "Launch Template",
          Icon: Server,
        },
        {
          label: "AWSLambda",
          category: NODE_CATEGORY.COMPUTE,
          description: "AWS Lambda",
          Icon: AWSLambdaIcon,
        },
        {
          label: "AWSSageMakerNotebookInstance",
          category: NODE_CATEGORY.COMPUTE,
          description: "SageMaker Notebook Instance",
          Icon: Bot,
        },
      ];

      for (const awsQueryNode of awsQueryNodes) {
        // When
        const visual = resolveNodeVisual(
          buildNode([awsQueryNode.label], { name: awsQueryNode.description }),
        );

        // Then
        expect(visual).toMatchObject({
          category: awsQueryNode.category,
          displayName: awsQueryNode.description,
          description: awsQueryNode.description,
          fallbackUsed: false,
        });
        expect(visual.Icon).toBe(awsQueryNode.Icon);
      }
    });
  });

  describe("fallback behavior", () => {
    it("should use formatted labels for unknown nodes and mark the fallback", () => {
      // Given
      const node = buildNode(["CustomGraphNode"]);

      // When
      const visual = resolveNodeVisual(node);

      // Then
      expect(visual).toMatchObject({
        category: NODE_CATEGORY.MISC,
        displayName: "Custom Graph Node",
        description: "Custom Graph Node",
        fallbackUsed: true,
      });
    });
  });
});
