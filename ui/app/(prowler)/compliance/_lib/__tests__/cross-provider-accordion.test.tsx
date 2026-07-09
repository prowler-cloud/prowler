import { describe, expect, it, vi } from "vitest";

import type { Framework } from "@/types/compliance";

// The requirement content component drags the findings/server-action chain
// into jsdom; assembly structure is what's under test here.
vi.mock(
  "@/components/compliance/compliance-accordion/client-accordion-content",
  () => ({ ClientAccordionContent: () => null }),
);
// The requirement title reaches next-auth through the shadcn/table barrel
// (data-table-pagination → @/lib). Same stubs as compliance-mapper.test.ts.
vi.mock(
  "@/components/compliance/compliance-accordion/compliance-accordion-requeriment-title",
  () => ({ ComplianceAccordionRequirementTitle: () => null }),
);
vi.mock(
  "@/components/compliance/compliance-accordion/compliance-accordion-title",
  () => ({ ComplianceAccordionTitle: () => null }),
);

import type { CrossProviderRequirementExtras } from "../../_types";
import { toCrossProviderAccordionItems } from "../cross-provider-accordion";

const data: Framework[] = [
  {
    name: "CSA-CCM",
    pass: 1,
    fail: 1,
    manual: 0,
    categories: [
      {
        name: "Audit & Assurance",
        pass: 1,
        fail: 1,
        manual: 0,
        controls: [
          {
            label: "Audit & Assurance",
            pass: 1,
            fail: 1,
            manual: 0,
            requirements: [
              {
                name: "A&A-01 - Audit Policy",
                description: "desc",
                status: "FAIL",
                pass: 0,
                fail: 1,
                manual: 0,
                check_ids: ["check_a"],
              },
              {
                name: "A&A-02 - Independent Assessments",
                description: "desc",
                status: "PASS",
                pass: 1,
                fail: 0,
                manual: 0,
                check_ids: [],
              },
            ],
          },
        ],
      },
    ],
  },
];

const extras = new Map<string, CrossProviderRequirementExtras>([
  [
    "A&A-01 - Audit Policy",
    {
      requirementId: "A&A-01",
      providers: { aws: "FAIL" },
      checkIdsByProvider: { aws: ["check_a"] },
      scanIdsByProvider: { aws: ["scan-1"] },
    },
  ],
]);

describe("toCrossProviderAccordionItems", () => {
  const items = toCrossProviderAccordionItems(data, extras, "CSA-CCM");

  it("keeps the per-scan accordion key scheme so ?section= deep links work", () => {
    expect(items).toHaveLength(1);
    expect(items[0].key).toBe("CSA-CCM-Audit & Assurance");
    expect(items[0].items).toHaveLength(2);
  });

  it("builds a title and content for every requirement, with or without extras", () => {
    for (const child of items[0].items ?? []) {
      expect(child.title).toBeTruthy();
      expect(child.content).toBeTruthy();
    }
  });
});
