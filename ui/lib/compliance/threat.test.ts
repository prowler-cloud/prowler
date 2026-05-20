import { describe, expect, it } from "vitest";

import { Framework, REQUIREMENT_STATUS } from "@/types/compliance";

import { getTopFailedSections } from "./threat-helpers";
import { THREATSCORE_PILLARS } from "./threatscore-pillars";

const buildFramework = (
  categoriesSpec: Array<{
    name: string;
    statuses: Array<"PASS" | "FAIL" | "MANUAL">;
  }>,
): Framework => ({
  name: "ProwlerThreatScore",
  pass: 0,
  fail: 0,
  manual: 0,
  categories: categoriesSpec.map((spec) => ({
    name: spec.name,
    pass: 0,
    fail: 0,
    manual: 0,
    controls: [
      {
        label: "control-0",
        pass: 0,
        fail: 0,
        manual: 0,
        requirements: spec.statuses.map((status, i) => ({
          name: `${spec.name}-req-${i}`,
          description: "",
          status: REQUIREMENT_STATUS[status],
          check_ids: [],
          pass: 0,
          fail: 0,
          manual: 0,
        })),
      },
    ],
  })),
});

describe("threat.getTopFailedSections", () => {
  it("returns every canonical pillar with zero-fill when no failures", () => {
    const data = [buildFramework([{ name: "1. IAM", statuses: ["PASS"] }])];
    const result = getTopFailedSections(data);

    expect(result.items.map((i) => i.name)).toEqual([...THREATSCORE_PILLARS]);
    expect(result.items.every((i) => i.total === 0)).toBe(true);
  });

  it("counts FAIL requirements per category and keeps canonical order", () => {
    const data = [
      buildFramework([
        { name: "1. IAM", statuses: ["FAIL", "FAIL"] },
        { name: "4. Encryption", statuses: ["FAIL"] },
      ]),
    ];
    const result = getTopFailedSections(data);

    expect(result.items).toEqual([
      { name: "1. IAM", total: 2 },
      { name: "2. Attack Surface", total: 0 },
      { name: "3. Logging and Monitoring", total: 0 },
      { name: "4. Encryption", total: 1 },
    ]);
  });

  it("appends non-canonical sections after the canonical ones", () => {
    const data = [
      buildFramework([
        { name: "1. IAM", statuses: ["FAIL"] },
        { name: "5. Data Protection", statuses: ["FAIL", "FAIL"] },
      ]),
    ];
    const result = getTopFailedSections(data);

    expect(result.items.map((i) => i.name)).toEqual([
      "1. IAM",
      "2. Attack Surface",
      "3. Logging and Monitoring",
      "4. Encryption",
      "5. Data Protection",
    ]);
    expect(
      result.items.find((i) => i.name === "5. Data Protection")?.total,
    ).toBe(2);
  });

  it("ignores PASS and MANUAL when counting failures", () => {
    const data = [
      buildFramework([
        { name: "1. IAM", statuses: ["PASS", "MANUAL", "FAIL", "PASS"] },
      ]),
    ];
    const result = getTopFailedSections(data);

    expect(result.items.find((i) => i.name === "1. IAM")?.total).toBe(1);
  });
});
