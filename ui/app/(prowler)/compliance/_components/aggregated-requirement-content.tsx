"use client";

import { ClientAccordionContent } from "@/components/compliance/compliance-accordion/client-accordion-content";
import type { CheckProviderTypesMap, Requirement } from "@/types/compliance";

interface AggregatedRequirementContentProps {
  requirement: Requirement;
  framework: string;
  scanIds: string[];
  emptyMessage: string;
  checkProviders?: CheckProviderTypesMap;
}

export const AggregatedRequirementContent = ({
  requirement,
  framework,
  scanIds,
  emptyMessage,
  checkProviders,
}: AggregatedRequirementContentProps) => {
  if (scanIds.length === 0) return <p className="text-sm">{emptyMessage}</p>;

  return (
    <ClientAccordionContent
      requirement={requirement}
      scanIds={scanIds}
      framework={framework}
      checkProviders={checkProviders}
      disableFindings={requirement.check_ids.length === 0}
    />
  );
};
