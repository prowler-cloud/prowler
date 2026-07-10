import { ComplianceAccordionTitle } from "@/components/compliance/compliance-accordion/compliance-accordion-title";
import type { AccordionItemProps } from "@/components/shadcn/accordion/Accordion";
import {
  type FindingStatus,
  StatusFindingBadge,
} from "@/components/shadcn/table/status-finding-badge";
import type { Framework } from "@/types/compliance";

import { CrossProviderRequirementContent } from "../_components/cross-provider-requirement-content";
import { RequirementProviderChips } from "../_components/requirement-provider-chips";
import type { CrossProviderRequirementExtras } from "../_types";

/**
 * Accordion assembly for the cross-provider detail. Mirrors the per-scan
 * mappers' `toAccordionItems` (same section key scheme, so `?section=` deep
 * links behave identically) but swaps the per-scan findings content for the
 * per-provider fan-out. Each requirement's status is shown once, on the same
 * row as the name and the expand chevron: via the per-provider chips when a
 * breakdown exists, or a single roll-up badge as a fallback. `extras` is the
 * map produced by `buildRequirementExtrasMap`, keyed by the mapper-composed
 * requirement name.
 */
export const toCrossProviderAccordionItems = (
  data: Framework[],
  extras: Map<string, CrossProviderRequirementExtras>,
  framework: string,
): AccordionItemProps[] =>
  data.flatMap((frameworkData) =>
    frameworkData.categories.map((category) => ({
      key: `${frameworkData.name}-${category.name}`,
      title: (
        <ComplianceAccordionTitle
          label={category.name}
          pass={category.pass}
          fail={category.fail}
          manual={category.manual}
          isParentLevel={true}
        />
      ),
      content: "",
      items: category.controls.flatMap((control) =>
        control.requirements.map((requirement, reqIndex) => {
          const requirementExtras = extras.get(requirement.name as string);

          return {
            key: `${frameworkData.name}-${category.name}-req-${reqIndex}`,
            title: (
              <div className="flex w-full items-center justify-between gap-3">
                <span className="min-w-0 truncate">
                  {requirement.name as string}
                </span>
                {/* Status shown once: the per-provider chips carry each
                    provider's status; only fall back to a roll-up badge when
                    no per-provider breakdown exists. */}
                {requirementExtras ? (
                  <RequirementProviderChips
                    providers={requirementExtras.providers}
                  />
                ) : (
                  <StatusFindingBadge
                    status={requirement.status as FindingStatus}
                  />
                )}
              </div>
            ),
            content: requirementExtras ? (
              <CrossProviderRequirementContent
                requirement={requirement}
                extras={requirementExtras}
                framework={framework}
              />
            ) : (
              <p className="text-sm">
                No per-provider breakdown is available for this requirement.
              </p>
            ),
            items: [],
          };
        }),
      ),
    })),
  );
