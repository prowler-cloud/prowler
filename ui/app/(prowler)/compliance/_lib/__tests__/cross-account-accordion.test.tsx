import { render, screen } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";

import type { Framework } from "@/types/compliance";

// Same stubs as the cross-provider accordion test: the requirement content
// drags the findings/server-action chain into jsdom, and the section header
// reaches next-auth through the shadcn/table barrel. Assembly structure is
// what's under test here.
vi.mock(
  "@/components/compliance/compliance-accordion/client-accordion-content",
  () => ({ ClientAccordionContent: () => null }),
);
vi.mock(
  "@/components/compliance/compliance-accordion/compliance-accordion-title",
  () => ({ ComplianceAccordionTitle: () => null }),
);

import type {
  CrossAccountAccountRef,
  CrossAccountRequirementExtras,
} from "../../_types";
import { toCrossAccountAccordionItems } from "../cross-account-accordion";

const ACC1 = "11111111-1111-4111-8111-111111111111";
const ACC2 = "22222222-2222-4222-8222-222222222222";

const accountMeta: CrossAccountAccountRef[] = [
  { id: ACC1, uid: "123456789012", alias: "prod" },
  { id: ACC2, uid: "210987654321", alias: null },
];

const data: Framework[] = [
  {
    name: "CIS",
    pass: 1,
    fail: 1,
    manual: 0,
    categories: [
      {
        name: "1. IAM",
        pass: 1,
        fail: 1,
        manual: 0,
        controls: [
          {
            label: "1. IAM",
            pass: 1,
            fail: 1,
            manual: 0,
            requirements: [
              {
                name: "1.1 - Maintain contact details",
                description: "desc",
                status: "FAIL",
                pass: 0,
                fail: 1,
                manual: 0,
                check_ids: ["check_a"],
              },
              {
                name: "1.2 - Security contact",
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

const extras = new Map<string, CrossAccountRequirementExtras>([
  [
    "1.1 - Maintain contact details",
    {
      requirementId: "1.1",
      accounts: { [ACC1]: "FAIL", [ACC2]: "PASS" },
      checkIds: ["check_a"],
      scanIdsByAccount: { [ACC1]: ["scan-1"], [ACC2]: ["scan-2"] },
    },
  ],
]);

describe("toCrossAccountAccordionItems", () => {
  const items = toCrossAccountAccordionItems(data, extras, "CIS", accountMeta);

  it("keeps the per-scan accordion key scheme so ?section= deep links work", () => {
    expect(items).toHaveLength(1);
    expect(items[0].key).toBe("CIS-1. IAM");
    expect(items[0].items).toHaveLength(2);
  });

  it("generates unique requirement keys across controls of one category", () => {
    // Two controls whose requirement lists both start at index 0 — keying
    // on the requirement index alone would collide (React duplicate-key
    // warning seen with CIS categories holding several controls).
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

    const keys = toCrossAccountAccordionItems(
      twoControls,
      extras,
      "CIS",
      accountMeta,
    )[0].items!.map((item) => item.key);

    expect(new Set(keys).size).toBe(keys.length);
  });

  it("shows one labeled chip per contributing account", () => {
    const { unmount } = render(<>{items[0].items?.[0].title}</>);

    expect(
      screen.getByText("1.1 - Maintain contact details"),
    ).toBeInTheDocument();
    // Both accounts contribute: alias when set, uid otherwise.
    expect(screen.getByText("prod")).toBeInTheDocument();
    expect(screen.getByText("210987654321")).toBeInTheDocument();
    expect(screen.getAllByText(/^fail$/i)).toHaveLength(1);
    expect(screen.getAllByText(/^pass$/i)).toHaveLength(1);
    unmount();
  });

  it("falls back to a single roll-up badge when a requirement has no per-account breakdown", () => {
    render(<>{items[0].items?.[1].title}</>);

    expect(screen.getByText("1.2 - Security contact")).toBeInTheDocument();
    expect(screen.getAllByText(/^pass$/i)).toHaveLength(1);
  });

  it("uses the control label as the row title for CIS-style 1:1 controls", () => {
    // The CIS mapper names requirements with the bare id and keeps the rich
    // "id - description" on its one-requirement control — the row must show
    // the rich label, matching the Single Scan view.
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

    const cisItems = toCrossAccountAccordionItems(
      cisStyle,
      new Map(),
      "CIS",
      accountMeta,
    );
    const { unmount } = render(<>{cisItems[0].items?.[0].title}</>);

    expect(
      screen.getByText("2.1.1 - Ensure centralized root access"),
    ).toBeInTheDocument();
    unmount();
  });

  it("keeps labeled multi-requirement controls as a nested level (ENS style)", () => {
    const ensStyle: Framework[] = [
      {
        ...data[0],
        categories: [
          {
            ...data[0].categories[0],
            controls: [
              {
                ...data[0].categories[0].controls[0],
                label: "op.acc - Access control group",
              },
            ],
          },
        ],
      },
    ];

    const ensItems = toCrossAccountAccordionItems(
      ensStyle,
      extras,
      "ENS",
      accountMeta,
    );

    // One nested control item wrapping its requirement rows.
    expect(ensItems[0].items).toHaveLength(1);
    expect(ensItems[0].items?.[0].items).toHaveLength(2);
  });

  it("keeps multi-framework data (ENS marcos) as the top accordion level", () => {
    const marcos: Framework[] = [
      { ...data[0], name: "Operacional" },
      { ...data[0], name: "Organizativo" },
    ];

    const marcoItems = toCrossAccountAccordionItems(
      marcos,
      extras,
      "ENS",
      accountMeta,
    );

    expect(marcoItems.map((item) => item.key)).toEqual([
      "Operacional",
      "Organizativo",
    ]);
    // Categories nest under their marco, keeping the per-scan key scheme.
    expect(marcoItems[0].items?.[0].key).toBe("Operacional-1. IAM");
  });

  it("shows the requirement type chip (requisito/recomendación) like per-scan", () => {
    const typed: Framework[] = [
      {
        ...data[0],
        categories: [
          {
            ...data[0].categories[0],
            controls: [
              {
                ...data[0].categories[0].controls[0],
                requirements: [
                  {
                    ...data[0].categories[0].controls[0].requirements[0],
                    type: "requisito",
                  },
                ],
              },
            ],
          },
        ],
      },
    ];

    const typedItems = toCrossAccountAccordionItems(
      typed,
      extras,
      "ENS",
      accountMeta,
    );
    const { unmount } = render(<>{typedItems[0].items?.[0].title}</>);

    expect(screen.getByText("requisito")).toBeInTheDocument();
    unmount();
  });
});
