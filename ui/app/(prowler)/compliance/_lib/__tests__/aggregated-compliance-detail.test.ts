import { describe, expect, it } from "vitest";

import type { AccordionItemProps } from "@/components/shadcn/accordion/Accordion";
import type { Framework } from "@/types/compliance";

import { getAggregatedInitialExpandedKeys } from "../aggregated-compliance-detail";

describe("getAggregatedInitialExpandedKeys", () => {
  it("returns the ancestor path for a nested section deep link", () => {
    const data = [
      { name: "Operational" },
      { name: "Organizational" },
    ] as Framework[];
    const accordionItems: AccordionItemProps[] = [
      {
        key: "Operational",
        title: null,
        content: null,
        items: [
          {
            key: "Operational-Access control",
            title: null,
            content: null,
          },
        ],
      },
    ];

    expect(
      getAggregatedInitialExpandedKeys(data, accordionItems, "Access control"),
    ).toEqual(["Operational", "Operational-Access control"]);
  });
});
