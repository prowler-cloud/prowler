import { describe, expect, it } from "vitest";

import {
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
