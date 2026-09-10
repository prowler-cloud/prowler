import type { AccordionItemProps } from "@/components/shadcn/accordion/Accordion";
import type { Framework } from "@/types/compliance";

import { CrossAccountRequirementContent } from "../_components/cross-account-requirement-content";
import { RequirementAccountChips } from "../_components/requirement-account-chips";
import type {
  CrossAccountAccountRef,
  CrossAccountRequirementExtras,
} from "../_types";

import { toAggregatedComplianceAccordionItems } from "./aggregated-compliance-accordion";

export const toCrossAccountAccordionItems = (
  data: Framework[],
  extras: Map<string, CrossAccountRequirementExtras>,
  framework: string,
  accountMeta: CrossAccountAccountRef[],
): AccordionItemProps[] =>
  toAggregatedComplianceAccordionItems({
    data,
    extras,
    renderStatus: (requirementExtras) => (
      <RequirementAccountChips
        accounts={requirementExtras.accounts}
        accountMeta={accountMeta}
      />
    ),
    renderContent: (requirement, requirementExtras, itemKey) => (
      <CrossAccountRequirementContent
        key={`content-${itemKey}`}
        requirement={requirement}
        extras={requirementExtras}
        accountMeta={accountMeta}
        framework={framework}
      />
    ),
    missingBreakdownMessage:
      "No per-account breakdown is available for this requirement.",
  });
