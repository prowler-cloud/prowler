import { describe, expect, it } from "vitest";

import type { AttackPathQuery, AttackPathScan } from "@/types/attack-paths";
import { ATTACK_PATH_QUERY_IDS } from "@/types/attack-paths";

import {
  attackPathsTour,
  type AttackPathsTourTarget,
  pickDemoQuery,
  pickDemoScan,
} from "../attack-paths.tour";

// Only these carry a `data-tour-id` in the page; keep in sync with tour:check.
const ALLOWED_TARGETS = [
  "intro",
  "scan-list",
  "query-selector",
  "execute-button",
] as const;

const definedTargets = (): AttackPathsTourTarget[] =>
  attackPathsTour.steps
    .map((step) => step.target)
    .filter((target): target is AttackPathsTourTarget => target !== undefined);

const makeScan = (overrides: {
  id: string;
  ready: boolean;
  provider: AttackPathScan["attributes"]["provider_type"];
}): AttackPathScan =>
  ({
    type: "attack-paths-scans",
    id: overrides.id,
    attributes: {
      graph_data_ready: overrides.ready,
      provider_type: overrides.provider,
    },
  }) as AttackPathScan;

const makeQuery = (overrides: {
  id: string;
  paramCount: number;
}): AttackPathQuery =>
  ({
    type: "attack-paths-scans",
    id: overrides.id,
    attributes: {
      parameters: Array.from({ length: overrides.paramCount }, (_, index) => ({
        name: `p${index}`,
      })),
    },
  }) as AttackPathQuery;

describe("attackPathsTour shape", () => {
  it("declares the attack-paths id", () => {
    expect(attackPathsTour.id).toBe("attack-paths");
  });

  it("never targets an element outside the allowed anchor set", () => {
    for (const target of definedTargets()) {
      expect(ALLOWED_TARGETS).toContain(target);
    }
  });
});

describe("pickDemoScan", () => {
  it("prefers a ready AWS scan over other ready scans", () => {
    const scans = [
      makeScan({ id: "gcp", ready: true, provider: "gcp" }),
      makeScan({ id: "aws", ready: true, provider: "aws" }),
    ];
    expect(pickDemoScan(scans)?.id).toBe("aws");
  });

  it("falls back to any ready scan when no ready AWS scan exists", () => {
    const scans = [
      makeScan({ id: "aws-not-ready", ready: false, provider: "aws" }),
      makeScan({ id: "gcp-ready", ready: true, provider: "gcp" }),
    ];
    expect(pickDemoScan(scans)?.id).toBe("gcp-ready");
  });

  it("returns undefined when no scan is ready", () => {
    const scans = [makeScan({ id: "x", ready: false, provider: "aws" })];
    expect(pickDemoScan(scans)).toBeUndefined();
  });
});

describe("pickDemoQuery", () => {
  it("prefers the IAM wildcard query when it is runnable", () => {
    const queries = [
      makeQuery({ id: "other", paramCount: 0 }),
      makeQuery({ id: "aws-iam-statements-allow-all-actions", paramCount: 0 }),
    ];
    expect(pickDemoQuery(queries)?.id).toBe(
      "aws-iam-statements-allow-all-actions",
    );
  });

  it("falls back to any parameter-free non-custom query", () => {
    const queries = [
      makeQuery({ id: ATTACK_PATH_QUERY_IDS.CUSTOM, paramCount: 0 }),
      makeQuery({ id: "needs-params", paramCount: 2 }),
      makeQuery({ id: "runnable", paramCount: 0 }),
    ];
    expect(pickDemoQuery(queries)?.id).toBe("runnable");
  });

  it("never picks the custom query (it needs Cypher input)", () => {
    const queries = [
      makeQuery({ id: ATTACK_PATH_QUERY_IDS.CUSTOM, paramCount: 0 }),
    ];
    expect(pickDemoQuery(queries)).toBeUndefined();
  });

  it("never picks a query with required parameters", () => {
    const queries = [makeQuery({ id: "needs-params", paramCount: 1 })];
    expect(pickDemoQuery(queries)).toBeUndefined();
  });
});
