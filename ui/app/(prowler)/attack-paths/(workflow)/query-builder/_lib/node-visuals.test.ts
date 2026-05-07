import { Globe2, KeyRound, Network, Server, UserRound } from "lucide-react";
import { describe, expect, it } from "vitest";

import {
  AmazonEC2Icon,
  AmazonS3Icon,
  AmazonVPCIcon,
  AWSAccountIcon,
  AWSIAMIcon,
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
      expect(visual.Icon).toBe(AWSAccountIcon);
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
      ["AWSAccount", NODE_CATEGORY.ACCOUNT, "AWS Account", AWSAccountIcon],
      ["S3Bucket", NODE_CATEGORY.STORAGE, "S3 Bucket", AmazonS3Icon],
      ["S3", NODE_CATEGORY.STORAGE, "S3", AmazonS3Icon],
      ["VPC", NODE_CATEGORY.NETWORK, "VPC", AmazonVPCIcon],
      ["Subnet", NODE_CATEGORY.NETWORK, "Subnet", Network],
      ["SecurityGroup", NODE_CATEGORY.NETWORK, "Security Group", Network],
      ["InternetGateway", NODE_CATEGORY.NETWORK, "Internet Gateway", Globe2],
      ["DefaultGateway", NODE_CATEGORY.NETWORK, "Default Gateway", Globe2],
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
      ["ServiceAccount", NODE_CATEGORY.IDENTITY, "Service Account", UserRound],
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
