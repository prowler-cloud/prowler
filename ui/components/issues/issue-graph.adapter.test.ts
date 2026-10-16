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

  it("caps the resources and skips findings on resources it did not draw", () => {
    const uids = Array.from(
      { length: GRAPH_RESOURCE_LIMIT + 3 },
      (_, i) => `arn:aws:s3:::${String.fromCharCode(97 + i)}`,
    ).reverse();

    const view = buildIssueGraph(issue(), uids);

    expect(view.nodes.filter((n) => n.id.startsWith("resource:"))).toHaveLength(
      GRAPH_RESOURCE_LIMIT,
    );
    // arn:aws:s3:::a and ::b are the last three after reversing, so not drawn.
    expect(view.nodes.some((n) => n.id.startsWith("finding:"))).toBe(false);
  });
});
