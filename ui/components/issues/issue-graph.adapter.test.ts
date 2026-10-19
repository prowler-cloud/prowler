import { describe, expect, it } from "vitest";

import {
  buildIssueGraph,
  GRAPH_RESOURCE_LIMIT,
} from "@/components/issues/issue-graph.adapter";
import { IssueAttributes } from "@/types/issues";

const leg = (state: string, evidence: string[] = []) => ({
  state,
  text: "",
  evidence,
});

const issue = (overrides: Partial<IssueAttributes> = {}) =>
  ({
    pattern: "aws_public_bucket",
    verdict: "likely",
    severity: "high",
    legs: {
      reachability: leg("yes", ["s3_bucket_public_access · arn:aws:s3:::a"]),
      access: leg("unknown"),
      target: leg("yes", ["s3_bucket_public_access · arn:aws:s3:::a"]),
      controls: leg("no", ["s3_bucket_default_encryption · arn:aws:s3:::b"]),
      verification: leg("no"),
    },
    ...overrides,
  }) as unknown as IssueAttributes;

const ids = (view: ReturnType<typeof buildIssueGraph>) =>
  view.nodes.map((n) => n.id);

describe("buildIssueGraph", () => {
  it("draws folded findings absent from leg evidence with their real severity", () => {
    // Given - only the instance is cited, but both security groups also have findings.
    const resources = ["instance", "security-group-ssh", "security-group-rdp"];
    const assessedIssue = issue();
    assessedIssue.legs.reachability.evidence = ["ssh · instance"];
    const findings = resources.map((resourceUid, index) => ({
      id: `finding-${index}`,
      checkId: index === 2 ? "rdp" : "ssh",
      checkTitle: index === 2 ? "RDP exposed" : "SSH exposed",
      severity: index === 0 ? ("critical" as const) : ("high" as const),
      resourceUid,
    }));

    // When
    const view = buildIssueGraph(assessedIssue, resources, findings);

    // Then - cited findings are not duplicated and every resource has its finding.
    expect(view.edges).toHaveLength(3);
    for (const finding of findings) {
      expect(view.nodes).toContainEqual(
        expect.objectContaining({
          id: `finding:${finding.checkId} · ${finding.resourceUid}`,
          properties: expect.objectContaining({
            finding_id: finding.id,
            check_title: finding.checkTitle,
            severity: finding.severity,
          }),
        }),
      );
    }
  });

  it("prioritizes folded findings over evidence-only resources at the graph limit", () => {
    // Given - the first 12 resources have evidence; the last has a folded finding.
    const resources = Array.from(
      { length: GRAPH_RESOURCE_LIMIT + 1 },
      (_, index) => `resource-${index}`,
    );
    const assessedIssue = issue();
    assessedIssue.legs.reachability.evidence = resources
      .slice(0, GRAPH_RESOURCE_LIMIT)
      .map((uid) => `supporting-check · ${uid}`);
    const resourceUid = resources[GRAPH_RESOURCE_LIMIT];
    // When
    const view = buildIssueGraph(assessedIssue, resources, [
      {
        id: "folded",
        checkId: "ssh",
        checkTitle: "SSH exposed",
        severity: "critical",
        resourceUid,
      },
    ]);
    // Then
    expect(view.nodes[0].id).toBe(`resource:${resourceUid}`);
    expect(ids(view)).toContain(`finding:ssh · ${resourceUid}`);
    expect(
      view.nodes.filter((node) => node.id.startsWith("resource:")),
    ).toHaveLength(GRAPH_RESOURCE_LIMIT);
  });

  it("draws only resource-to-finding evidence associations", () => {
    const view = buildIssueGraph(issue(), ["arn:aws:s3:::a", "arn:aws:s3:::b"]);

    expect(ids(view)).toEqual([
      "resource:arn:aws:s3:::a",
      "resource:arn:aws:s3:::b",
      // The same evidence line on two legs is one finding.
      "finding:s3_bucket_public_access · arn:aws:s3:::a",
      "finding:s3_bucket_default_encryption · arn:aws:s3:::b",
    ]);
    expect(view.nodes[0]).toMatchObject({
      labels: ["S3Bucket"],
      properties: { name: "a" },
    });
    expect(view.edges).toContainEqual(
      expect.objectContaining({
        source: "resource:arn:aws:s3:::b",
        target: "finding:s3_bucket_default_encryption · arn:aws:s3:::b",
        type: "HAS_FINDING",
      }),
    );
    expect(view.nodes.at(-1)?.properties).not.toHaveProperty("severity");
    expect(view.nodes.at(-1)?.properties).toMatchObject({
      check_id: "s3_bucket_default_encryption",
      resource_uid: "arn:aws:s3:::b",
    });
  });

  it.each(["yes", "no", "partial", "unknown"])(
    "does not infer per-resource Internet reachability from aggregate %s",
    (state) => {
      const view = buildIssueGraph(
        issue({ legs: { reachability: leg(state) } } as never),
        ["arn:aws:s3:::a"],
      );

      expect(ids(view)).not.toContain("internet");
      expect(view.edges.map((e) => e.source)).not.toContain("internet");
    },
  );

  it("prioritizes resources with evidence before applying the graph limit", () => {
    // Given - evidence belongs to resources beyond the initial graph limit.
    const uids = Array.from(
      { length: GRAPH_RESOURCE_LIMIT + 3 },
      (_, i) => `arn:aws:s3:::${String.fromCharCode(97 + i)}`,
    ).reverse();

    // When
    const view = buildIssueGraph(issue(), uids);

    // Then - both findings remain visible within the resource limit.
    expect(view.nodes.filter((n) => n.id.startsWith("resource:"))).toHaveLength(
      GRAPH_RESOURCE_LIMIT,
    );
    expect(ids(view)).toEqual(
      expect.arrayContaining([
        "resource:arn:aws:s3:::a",
        "resource:arn:aws:s3:::b",
        "finding:s3_bucket_public_access · arn:aws:s3:::a",
        "finding:s3_bucket_default_encryption · arn:aws:s3:::b",
      ]),
    );
  });

  it("keeps the limit and skips findings whose resources do not fit", () => {
    // Given - more evidence-bearing resources than the graph can display.
    const uids = Array.from(
      { length: GRAPH_RESOURCE_LIMIT + 1 },
      (_, i) => `resource-${i}`,
    );
    const assessedIssue = issue();
    assessedIssue.legs.reachability.evidence = uids.map(
      (uid) => `check · ${uid}`,
    );

    // When
    const view = buildIssueGraph(assessedIssue, uids);

    // Then - preserve input order and never leave an edge without its resource.
    expect(
      view.nodes.filter((node) => node.id.startsWith("resource:")),
    ).toHaveLength(GRAPH_RESOURCE_LIMIT);
    expect(view.edges).toHaveLength(GRAPH_RESOURCE_LIMIT);
    expect(ids(view)).not.toContain(
      `finding:check · resource-${GRAPH_RESOURCE_LIMIT}`,
    );
    for (const edge of view.edges) {
      expect(ids(view)).toContain(edge.source);
      expect(ids(view)).toContain(edge.target);
    }
    expect(uids[0]).toBe("resource-0");
  });

  it.each([
    { evidence: [] },
    { evidence: ["malformed", " · resource-12", "check · unrelated-resource"] },
  ])(
    "preserves resource order without matching valid evidence: $evidence",
    ({ evidence }) => {
      // Given
      const uids = Array.from(
        { length: GRAPH_RESOURCE_LIMIT + 1 },
        (_, i) => `resource-${i}`,
      );
      const assessedIssue = issue();
      assessedIssue.legs.reachability.evidence = evidence;

      // When
      const view = buildIssueGraph(assessedIssue, uids);

      // Then
      expect(ids(view)).toEqual(
        uids.slice(0, GRAPH_RESOURCE_LIMIT).map((uid) => `resource:${uid}`),
      );
      expect(view.edges).toEqual([]);
    },
  );
});
