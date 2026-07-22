import { render, screen } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";

import type { Framework } from "@/types/compliance";

// The requirement content component drags the findings/server-action chain
// into jsdom; assembly structure is what's under test here.
vi.mock(
  "@/components/compliance/compliance-accordion/client-accordion-content",
  () => ({ ClientAccordionContent: () => null }),
);
// The section header reaches next-auth through the shadcn/table barrel
// (data-table-pagination → @/lib). Same stub as compliance-mapper.test.ts.
// The requirement title is rendered for real here — it only pulls the
// leak-free status-finding-badge file + provider icons.
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

  it("uses the control label as the row title for CIS-style 1:1 controls", () => {
    const cisStyle: Framework[] = [
      {
        ...data[0],
        categories: [
          {
            ...data[0].categories[0],
            controls: [
              {
                label: "2.1.1 - Ensure centralized root access",
                pass: 0,
                fail: 1,
                manual: 0,
                requirements: [
                  {
                    ...data[0].categories[0].controls[0].requirements[0],
                    name: "2.1.1",
                  },
                ],
              },
            ],
          },
        ],
      },
    ];

    const cisItems = toCrossProviderAccordionItems(cisStyle, new Map(), "CIS");
    const { unmount } = render(<>{cisItems[0].items?.[0].title}</>);

    expect(
      screen.getByText("2.1.1 - Ensure centralized root access"),
    ).toBeInTheDocument();
    unmount();
  });

  it("generates unique requirement keys across controls of one category", () => {
    // Two controls whose requirement lists both start at index 0 — keying
    // on the requirement index alone would collide (React duplicate-key
    // warning seen on the cross-account sibling with CIS categories).
    const twoControls: Framework[] = [
      {
        ...data[0],
        categories: [
          {
            ...data[0].categories[0],
            controls: [
              data[0].categories[0].controls[0],
              {
                ...data[0].categories[0].controls[0],
                label: "another control",
              },
            ],
          },
        ],
      },
    ];

    const keys = toCrossProviderAccordionItems(
      twoControls,
      extras,
      "CSA-CCM",
    )[0].items!.map((item) => item.key);

    expect(new Set(keys).size).toBe(keys.length);
  });

  it("shows the status only once via the provider chips (no duplicate roll-up badge)", () => {
    // A&A-01 has a single provider (aws FAIL): its status must appear once,
    // in the chip — not also as a separate roll-up badge.
    const { unmount } = render(<>{items[0].items?.[0].title}</>);

    expect(screen.getByText("A&A-01 - Audit Policy")).toBeInTheDocument();
    expect(screen.getAllByText(/^fail$/i)).toHaveLength(1);
    unmount();
  });

  it("falls back to a single roll-up badge when a requirement has no per-provider breakdown", () => {
    // A&A-02 is absent from the extras map, so it keeps one roll-up status.
    render(<>{items[0].items?.[1].title}</>);

    expect(
      screen.getByText("A&A-02 - Independent Assessments"),
    ).toBeInTheDocument();
    expect(screen.getAllByText(/^pass$/i)).toHaveLength(1);
  });
});
