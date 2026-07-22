import { describe, expect, it } from "vitest";

import {
  buildAttackPathContext,
  buildComplianceContext,
  buildFindingGroupContext,
  buildFindingResourceContext,
  buildFindingSummaryContext,
  buildFocusedFindingContext,
  buildFocusedResourceContext,
  buildProviderContext,
  buildProviderSummaryContext,
  buildResourceContext,
  buildResourceSummaryContext,
  buildScanContext,
  buildScanSummaryContext,
} from "./contributions";

describe("Lighthouse page contributions", () => {
  it("builds a bounded findings summary from existing pagination metadata", () => {
    expect(buildFindingSummaryContext(42)).toEqual({
      kind: "finding",
      id: "summary",
      source: "automatic",
      scopeKey: "findings:/findings",
      label: "42 findings",
      findingId: "summary",
      total: 42,
    });
  });

  it("builds selected finding group and resource snapshots", () => {
    expect(
      buildFindingGroupContext({
        id: "group-1",
        checkId: "aws_s3_bucket_public_access",
        checkTitle: "S3 bucket allows public access",
        severity: "critical",
        status: "FAIL",
      }),
    ).toMatchObject({
      kind: "finding",
      id: "group-1",
      source: "selection",
      scopeKey: "findings:/findings",
      findingId: "group-1",
      checkId: "aws_s3_bucket_public_access",
      severity: "critical",
      status: "FAIL",
    });
    expect(
      buildFindingResourceContext({
        findingId: "finding-2",
        checkId: "aws_s3_bucket_public_access",
        severity: "critical",
        status: "FAIL",
        providerUid: "123456789012",
        resourceUid: "arn:aws:s3:::example",
        region: "eu-west-1",
      }),
    ).toMatchObject({
      id: "finding-2",
      findingId: "finding-2",
      source: "selection",
      checkId: "aws_s3_bucket_public_access",
      severity: "critical",
      status: "FAIL",
      providerUid: "123456789012",
      resourceUid: "arn:aws:s3:::example",
      region: "eu-west-1",
    });
  });

  it("builds a focused finding for the owning page scope", () => {
    // Given / When
    const context = buildFocusedFindingContext({
      pathname: "/attack-paths",
      findingId: "finding-2",
      checkId: "aws_s3_bucket_public_access",
      severity: "critical",
      status: "FAIL",
      providerUid: "123456789012",
      resourceUid: "arn:aws:s3:::example",
      region: "eu-west-1",
    });

    // Then
    expect(context).toEqual({
      kind: "finding",
      id: "finding-2",
      source: "focused",
      scopeKey: "attack-paths:/attack-paths",
      label: "Focused finding",
      findingId: "finding-2",
      checkId: "aws_s3_bucket_public_access",
      severity: "critical",
      status: "FAIL",
      providerUid: "123456789012",
      resourceUid: "arn:aws:s3:::example",
      region: "eu-west-1",
    });
  });

  it("builds resource summary and selected resource snapshots", () => {
    expect(buildResourceSummaryContext(17)).toMatchObject({
      kind: "resource",
      id: "summary",
      source: "automatic",
      scopeKey: "resources:/resources",
      resourceId: "summary",
      total: 17,
    });

    expect(
      buildResourceContext({
        id: "resource-1",
        attributes: {
          uid: "arn:aws:s3:::example",
          service: "s3",
          region: "eu-west-1",
          type: "AwsS3Bucket",
          failed_findings_count: 3,
        },
        providerUid: "123456789012",
      }),
    ).toEqual({
      kind: "resource",
      id: "resource-1",
      source: "selection",
      scopeKey: "resources:/resources",
      label: "Selected resource",
      resourceId: "resource-1",
      resourceUid: "arn:aws:s3:::example",
      providerUid: "123456789012",
      service: "s3",
      region: "eu-west-1",
      resourceType: "AwsS3Bucket",
      failedFindingsCount: 3,
    });
  });

  it("builds a focused resource for the owning page scope", () => {
    // Given / When
    const context = buildFocusedResourceContext({
      pathname: "/resources",
      id: "resource-1",
      attributes: {
        uid: "arn:aws:s3:::example",
        service: "s3",
        region: "eu-west-1",
        type: "AwsS3Bucket",
        failed_findings_count: 3,
      },
      providerUid: "123456789012",
    });

    // Then
    expect(context).toEqual({
      kind: "resource",
      id: "resource-1",
      source: "focused",
      scopeKey: "resources:/resources",
      label: "Focused resource",
      resourceId: "resource-1",
      resourceUid: "arn:aws:s3:::example",
      providerUid: "123456789012",
      service: "s3",
      region: "eu-west-1",
      resourceType: "AwsS3Bucket",
      failedFindingsCount: 3,
    });
  });

  it("builds compliance framework snapshots with score and totals", () => {
    expect(
      buildComplianceContext({
        pathname: "/compliance/cis-aws",
        id: "cis_aws_1.5",
        framework: "CIS AWS Foundations",
        version: "1.5",
        scanId: "scan-1",
        providerUid: "123456789012",
        mode: "per-scan",
        section: "IAM",
        region: "eu-west-1",
        passed: 8,
        failed: 2,
        total: 10,
      }),
    ).toEqual({
      kind: "compliance",
      id: "cis_aws_1.5",
      source: "automatic",
      scopeKey: "compliance-detail:/compliance/cis-aws",
      label: "CIS AWS Foundations",
      framework: "CIS AWS Foundations",
      version: "1.5",
      scanId: "scan-1",
      providerUid: "123456789012",
      mode: "per-scan",
      section: "IAM",
      region: "eu-west-1",
      score: 80,
      totals: { passed: 8, failed: 2, total: 10 },
    });
  });

  it("builds an attack-path snapshot and excludes unsafe query parameters", () => {
    expect(
      buildAttackPathContext({
        pathname: "/attack-paths/query-builder",
        scanId: "scan-1",
        queryId: "internet-exposed",
        queryLabel: "Internet exposed resources",
        parameters: {
          region: "eu-west-1",
          hops: 3,
          includeMuted: false,
          password: "do-not-send",
          query: "MATCH (n) RETURN n",
          ownerEmail: "security@example.com",
          sourceIp: "10.0.0.1",
          sourceIpv6: "2001:db8::1",
          authHeader: "Bearer sensitive-value",
        },
        nodeCount: 12,
        edgeCount: 15,
        selectedNode: { id: "node-1", type: "AwsS3Bucket" },
      }),
    ).toEqual({
      kind: "attack_path",
      id: "current-query",
      source: "automatic",
      scopeKey: "attack-paths:/attack-paths/query-builder",
      label: "Internet exposed resources",
      scanId: "scan-1",
      queryId: "internet-exposed",
      parameters: {
        region: "eu-west-1",
        hops: 3,
        includeMuted: false,
      },
      nodeCount: 12,
      edgeCount: 15,
      selectedNodeId: "node-1",
      selectedNodeType: "AwsS3Bucket",
    });
  });

  it("builds an attack-path scope from the current route", () => {
    // Given / When
    const context = buildAttackPathContext({
      pathname: "/attack-paths",
      scanId: "scan-1",
    });

    // Then
    expect(context.scopeKey).toBe("attack-paths:/attack-paths");
  });

  it("builds scan summary and selected scan snapshots", () => {
    expect(buildScanSummaryContext(9, "completed")).toEqual({
      kind: "scan",
      id: "summary",
      source: "automatic",
      scopeKey: "scans:/scans",
      label: "9 completed scans",
      state: "completed",
      total: 9,
    });
    expect(
      buildScanContext({
        id: "scan-1",
        state: "failed",
        providerUid: "123456789012",
      }),
    ).toMatchObject({
      id: "scan-1",
      scanId: "scan-1",
      state: "failed",
      providerUid: "123456789012",
      source: "selection",
    });
  });

  it("builds provider summary and selected provider snapshots", () => {
    expect(buildProviderSummaryContext(4)).toMatchObject({
      kind: "provider",
      id: "summary",
      source: "automatic",
      scopeKey: "providers:/providers",
      total: 4,
    });
    expect(
      buildProviderContext({
        id: "provider-1",
        uid: "123456789012",
        type: "aws",
      }),
    ).toMatchObject({
      id: "provider-1",
      providerId: "provider-1",
      providerUid: "123456789012",
      providerType: "aws",
      source: "selection",
    });
  });
});
