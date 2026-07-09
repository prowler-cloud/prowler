"use client";

import { ClientAccordionContent } from "@/components/compliance/compliance-accordion/client-accordion-content";
import { ProviderTypeIcon } from "@/components/icons/providers-badge/provider-type-icon";
import { Accordion } from "@/components/shadcn/accordion/Accordion";
import {
  type FindingStatus,
  StatusFindingBadge,
} from "@/components/shadcn/table/status-finding-badge";
import type { Requirement } from "@/types/compliance";
import {
  PROVIDER_DISPLAY_NAMES,
  PROVIDER_TYPES,
  type ProviderType,
} from "@/types/providers";

import type { CrossProviderRequirementExtras } from "../_types";

interface CrossProviderRequirementContentProps {
  /** The requirement as produced by the framework mapper (roll-up level). */
  requirement: Requirement;
  extras: CrossProviderRequirementExtras;
  framework: string;
}

interface ProviderScanSection {
  provider: ProviderType;
  scanId: string;
  label: string;
}

/**
 * Per-provider findings fan-out for a cross-provider requirement: one
 * collapsed section per contributing provider scan, each rendering the
 * existing per-scan `ClientAccordionContent` with a requirement narrowed to
 * that provider's check ids and status. Sections mount lazily (the shared
 * Accordion unmounts collapsed content), so no findings are fetched until a
 * provider is expanded.
 *
 * Note: the API keys statuses by provider TYPE, not account — with several
 * accounts of one type each account's scan gets its own findings section but
 * they share the type-level roll-up status.
 */
export const CrossProviderRequirementContent = ({
  requirement,
  extras,
  framework,
}: CrossProviderRequirementContentProps) => {
  const sections: ProviderScanSection[] = PROVIDER_TYPES.filter(
    (type) => extras.providers[type],
  ).flatMap((type) => {
    const scanIds = extras.scanIdsByProvider[type] ?? [];
    return scanIds.map((scanId, index) => ({
      provider: type,
      scanId,
      label:
        scanIds.length > 1
          ? `${PROVIDER_DISPLAY_NAMES[type]} — account ${index + 1} of ${scanIds.length}`
          : PROVIDER_DISPLAY_NAMES[type],
    }));
  });

  if (sections.length === 0) {
    return (
      <p className="text-sm">
        No provider scan contributed to this requirement with the current
        filters.
      </p>
    );
  }

  const items = sections.map((section) => {
    const providerStatus = extras.providers[section.provider] ?? "MANUAL";
    const providerCheckIds =
      extras.checkIdsByProvider[section.provider] ?? requirement.check_ids;

    // Narrow the mapped requirement to this provider: same detail fields
    // (so getDetailsComponent keeps working), provider-scoped check ids and
    // status for the findings query underneath.
    const providerRequirement: Requirement = {
      ...requirement,
      check_ids: providerCheckIds,
      status: providerStatus,
    };

    return {
      key: `${section.provider}-${section.scanId}`,
      title: (
        <div className="flex items-center gap-2">
          <ProviderTypeIcon type={section.provider} size={16} />
          <span>{section.label}</span>
          <StatusFindingBadge
            status={providerStatus as FindingStatus}
            size="sm"
          />
        </div>
      ),
      content: (
        <ClientAccordionContent
          requirement={providerRequirement}
          scanId={section.scanId}
          framework={framework}
          disableFindings={providerCheckIds.length === 0}
        />
      ),
    };
  });

  return <Accordion items={items} variant="light" isCompact />;
};
