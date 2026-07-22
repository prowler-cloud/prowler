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

  const findExpandedPath = (
    items: AccordionItemProps[],
    ancestors: string[] = [],
  ): string[] | undefined => {
    for (const item of items) {
      const path = [...ancestors, item.key];
      if (candidates.has(item.key)) return path;

      const nestedMatch = findExpandedPath(item.items ?? [], path);
      if (nestedMatch) return nestedMatch;
    }

    return undefined;
  };

  return findExpandedPath(accordionItems) ?? [];
};
