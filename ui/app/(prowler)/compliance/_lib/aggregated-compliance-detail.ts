import type { AccordionItemProps } from "@/components/shadcn/accordion/Accordion";
import type { Framework, RequirementsTotals } from "@/types/compliance";

export const getAggregatedRequirementsTotals = (
  data: Framework[],
): RequirementsTotals =>
  data.reduce(
    (totals, framework) => ({
      pass: totals.pass + framework.pass,
      fail: totals.fail + framework.fail,
      manual: totals.manual + framework.manual,
    }),
    { pass: 0, fail: 0, manual: 0 },
  );

export const getAggregatedInitialExpandedKeys = (
  data: Framework[],
  accordionItems: AccordionItemProps[],
  targetSection?: string,
): string[] => {
  if (!targetSection) return [];

  const candidates = new Set(
    data.map((framework) => `${framework.name}-${targetSection}`),
  );
  const match = accordionItems.find((item) => candidates.has(item.key));
  return match ? [match.key] : [];
};
