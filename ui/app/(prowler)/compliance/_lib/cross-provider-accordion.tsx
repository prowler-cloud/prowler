import type { AccordionItemProps } from "@/components/shadcn/accordion/Accordion";
import type { Framework } from "@/types/compliance";

import { CrossProviderRequirementContent } from "../_components/cross-provider-requirement-content";
import { RequirementProviderChips } from "../_components/requirement-provider-chips";
import type { CrossProviderRequirementExtras } from "../_types";

import { toAggregatedComplianceAccordionItems } from "./aggregated-compliance-accordion";

export const toCrossProviderAccordionItems = (
  data: Framework[],
  extras: Map<string, CrossProviderRequirementExtras>,
  framework: string,
): AccordionItemProps[] =>
  toAggregatedComplianceAccordionItems({
    data,
    extras,
    renderStatus: (requirementExtras) => (
      <RequirementProviderChips providers={requirementExtras.providers} />
    ),
    renderContent: (requirement, requirementExtras, itemKey) => (
      <CrossProviderRequirementContent
        key={`content-${itemKey}`}
        requirement={requirement}
        extras={requirementExtras}
        framework={framework}
      />
    ),
    missingBreakdownMessage:
      "No per-provider breakdown is available for this requirement.",
  });
