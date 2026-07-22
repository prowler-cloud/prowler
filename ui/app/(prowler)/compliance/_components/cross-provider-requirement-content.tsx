"use client";

import type { Requirement } from "@/types/compliance";
import { PROVIDER_TYPES } from "@/types/providers";

import { invertCheckIdsByProvider } from "../_lib/cross-provider-adapter";
import type { CrossProviderRequirementExtras } from "../_types";

import { AggregatedRequirementContent } from "./aggregated-requirement-content";

interface CrossProviderRequirementContentProps {
  /** The requirement as produced by the framework mapper (roll-up level). */
  requirement: Requirement;
  extras: CrossProviderRequirementExtras;
  framework: string;
}

/**
 * Combined findings view for a cross-provider requirement: the requirement
 * detail rendered once, one checks list labeling each check with its provider
 * types, and a single findings table querying every contributing scan at once
 * (each row carries its own provider column). Mounts lazily — the requirement
 * accordion unmounts collapsed content, so the combined fetch only fires on
 * expand.
 */
export const CrossProviderRequirementContent = ({
  requirement,
  extras,
  framework,
}: CrossProviderRequirementContentProps) => {
  const contributingTypes = PROVIDER_TYPES.filter(
    (type) => extras.providers[type],
  );

  const scanIds = Array.from(
    new Set(
      contributingTypes.flatMap((type) => extras.scanIdsByProvider[type] ?? []),
    ),
  );

  return (
    <AggregatedRequirementContent
      requirement={requirement}
      scanIds={scanIds}
      framework={framework}
      checkProviders={invertCheckIdsByProvider(extras.checkIdsByProvider)}
      emptyMessage="No provider scan contributed to this requirement with the current filters."
    />
  );
};
