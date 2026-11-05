import { describe, expect, it } from "vitest";

import { ATTACK_PATH_QUERY_KIND } from "@/types/attack-paths";

import { LIGHTHOUSE_COMPLIANCE_CONTEXT_MODE } from "./constants";
import {
  buildAlertSummaryContext,
  buildAttackPathContext,
  buildComplianceContext,
  buildFilteredProviderContext,
  buildFindingGroupContext,
  buildFindingResourceContext,
  buildFindingSeveritySummaryContext,
  buildFindingStatusSummaryContext,
  buildFindingSummaryContext,
  buildFocusedAlertContext,
  buildFocusedFindingContext,
  buildFocusedResourceContext,
  buildProviderContext,
  buildProviderGroupContext,
  buildProviderSummaryContext,
  buildResourceContext,
  buildResourceSummaryContext,
  buildScanContext,
  buildScanSummaryContext,
  buildServiceSummaryContext,
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
        mode: LIGHTHOUSE_COMPLIANCE_CONTEXT_MODE.PER_SCAN,
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

  it("builds an enriched ThreatScore snapshot with delta and weakest section", () => {
    expect(
      buildComplianceContext({
        pathname: "/",
        id: "prowler-threat-score",
        framework: "Prowler ThreatScore",
        score: 62.4,
        scoreDelta: -3.21,
        criticalRequirementsCount: 5,
        worstSection: "1.2 Attack Surface",
        worstSectionScore: 38.6,
        passed: 120,
        failed: 40,
        total: 160,
      }),
    ).toEqual({
      kind: "compliance",
      id: "prowler-threat-score",
      source: "automatic",
      scopeKey: "overview:/",
      label: "Prowler ThreatScore",
      framework: "Prowler ThreatScore",
      score: 62.4,
      scoreDelta: -3.21,
      criticalRequirementsCount: 5,
      worstSection: "1.2 Attack Surface",
      worstSectionScore: 38.6,
      totals: { passed: 120, failed: 40, total: 160 },
    });
  });

  it("builds a bounded alert rules summary", () => {
    expect(buildAlertSummaryContext(12, 9)).toEqual({
      kind: "alert",
      id: "summary",
      source: "automatic",
      scopeKey: "alerts:/alerts",
      label: "12 alert rules",
      total: 12,
      enabledCount: 9,
    });
  });

  it("builds a focused snapshot for the alert rule being edited", () => {
    expect(
      buildFocusedAlertContext({
        id: "alert-1",
        name: "Critical S3 findings",
        trigger: "new_failing_findings",
        enabled: true,
      }),
    ).toEqual({
      kind: "alert",
      id: "alert-1",
      source: "focused",
      scopeKey: "alerts:/alerts",
      label: "Critical S3 findings",
      alertId: "alert-1",
      trigger: "new_failing_findings",
      enabled: true,
    });
  });

  it("builds an overview findings status summary", () => {
    expect(
      buildFindingStatusSummaryContext({
        pathname: "/",
        passed: 320,
        failed: 80,
        newPassed: 12,
        newFailed: 7,
      }),
    ).toEqual({
      kind: "finding",
      id: "status-summary",
      source: "automatic",
      scopeKey: "overview:/",
      label: "80 failed / 320 passed findings",
      findingId: "status-summary",
      passed: 320,
      failed: 80,
      newPassed: 12,
      newFailed: 7,
    });
  });

  it("builds an overview severity summary for failing findings", () => {
    expect(
      buildFindingSeveritySummaryContext({
        pathname: "/",
        severityCounts: {
          critical: 4,
          high: 18,
          medium: 40,
          low: 15,
          informational: 3,
        },
      }),
    ).toEqual({
      kind: "finding",
      id: "severity-summary",
      source: "automatic",
      scopeKey: "overview:/",
      label: "Failing findings by severity",
      findingId: "severity-summary",
      severityCounts: {
        critical: 4,
        high: 18,
        medium: 40,
        low: 15,
        informational: 3,
      },
    });
  });

  it("builds an automatic summary for the riskiest service", () => {
    expect(
      buildServiceSummaryContext({
        pathname: "/",
        service: "s3",
        failedFindingsCount: 34,
        total: 120,
      }),
    ).toEqual({
      kind: "resource",
      id: "service-s3",
      source: "automatic",
      scopeKey: "overview:/",
      label: "Service: s3",
      resourceId: "service-s3",
      service: "s3",
      failedFindingsCount: 34,
      total: 120,
    });
  });

  it("builds automatic provider context for URL-filtered providers", () => {
    expect(
      buildFilteredProviderContext({
        pathname: "/",
        id: "prov-1",
        uid: "123456789012",
        type: "aws",
        alias: "Production",
      }),
    ).toEqual({
      kind: "provider",
      id: "prov-1",
      source: "automatic",
      scopeKey: "overview:/",
      label: "Provider: Production",
      providerId: "prov-1",
      providerUid: "123456789012",
      providerType: "aws",
    });
  });

  it("builds automatic context for a URL-filtered provider group", () => {
    expect(
      buildProviderGroupContext({
        pathname: "/",
        id: "group-uuid-1",
        name: "Production accounts",
      }),
    ).toEqual({
      kind: "provider",
      id: "group-group-uuid-1",
      source: "automatic",
      scopeKey: "overview:/",
      label: "Provider group: Production accounts",
    });
  });

  it("defines every supported compliance context mode", () => {
    expect(Object.values(LIGHTHOUSE_COMPLIANCE_CONTEXT_MODE)).toEqual([
      "per-scan",
      "cross-provider",
      "cross-account",
    ]);
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
      redactedParameters: [
        "authHeader",
        "ownerEmail",
        "password",
        "query",
        "sourceIp",
        "sourceIpv6",
      ],
      nodeCount: 12,
      edgeCount: 15,
      selectedNodeId: "node-1",
      selectedNodeType: "AwsS3Bucket",
    });
  });

  it("describes custom-query results without exposing the Cypher or raw graph ids", () => {
    // Given
    const context = buildAttackPathContext({
      pathname: "/attack-paths",
      scanId: "scan-1",
      queryId: "__custom-open-cypher__",
      queryLabel: "Custom openCypher query",
      queryKind: ATTACK_PATH_QUERY_KIND.CUSTOM,
      parameters: {
        query: "MATCH path = (a)-[r]->(b) RETURN path LIMIT 25",
      },
      graphData: {
        nodes: [
          { id: "account-1", labels: ["AWSAccount"], properties: {} },
          { id: "role-1", labels: ["AWSRole"], properties: {} },
          { id: "bucket-1", labels: ["S3Bucket"], properties: {} },
          { id: "instance-1", labels: ["EC2Instance"], properties: {} },
        ],
        relationships: [
          {
            id: "relationship-1",
            source: "account-1",
            target: "role-1",
            label: "RESOURCE",
          },
          {
            id: "relationship-2",
            source: "bucket-1",
            target: "instance-1",
            label: "CAN_ACCESS",
          },
        ],
      },
    });

    // Then
    expect(context).toMatchObject({
      queryKind: "custom",
      canReplayQuery: false,
      redactedParameters: ["query"],
      nodeCount: 4,
      edgeCount: 2,
      connectedComponentCount: 2,
      nodeTypeCounts: {
        AWSAccount: 1,
        AWSRole: 1,
        EC2Instance: 1,
        S3Bucket: 1,
      },
      relationshipTypeCounts: {
        CAN_ACCESS: 1,
        RESOURCE: 1,
      },
    });
    expect(JSON.stringify(context)).not.toContain("MATCH path");
    expect(JSON.stringify(context)).not.toContain("account-1");
  });

  it("marks a predefined query as non-replayable when a required IP is redacted", () => {
    // Given
    const parameters = { ip: "192.0.2.10" };

    // When
    const context = buildAttackPathContext({
      pathname: "/attack-paths",
      scanId: "scan-1",
      queryId: "aws-public-ip-resource-lookup",
      queryLabel: "Resource Lookup by Public IP",
      queryKind: ATTACK_PATH_QUERY_KIND.PREDEFINED,
      parameters,
    });

    // Then
    expect(context).toMatchObject({
      queryKind: "predefined",
      canReplayQuery: false,
      redactedParameters: ["ip"],
    });
    expect(context.parameters).toBeUndefined();
  });

  it("marks a predefined query without redacted parameters as replayable", () => {
    // Given / When
    const context = buildAttackPathContext({
      pathname: "/attack-paths",
      scanId: "scan-1",
      queryId: "aws-internet-exposed-resources",
      queryLabel: "Internet-exposed resources",
      queryKind: ATTACK_PATH_QUERY_KIND.PREDEFINED,
      parameters: { region: "eu-west-1" },
    });

    // Then
    expect(context).toMatchObject({
      queryKind: "predefined",
      canReplayQuery: true,
      parameters: { region: "eu-west-1" },
    });
    expect(context.redactedParameters).toBeUndefined();
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
