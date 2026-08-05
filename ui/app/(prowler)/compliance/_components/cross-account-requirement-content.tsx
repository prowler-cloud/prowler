"use client";

import type { Requirement } from "@/types/compliance";

import type {
  CrossAccountAccountRef,
  CrossAccountRequirementExtras,
} from "../_types";

import { AggregatedRequirementContent } from "./aggregated-requirement-content";

interface CrossAccountRequirementContentProps {
  /** The requirement as produced by the framework mapper (roll-up level). */
  requirement: Requirement;
  extras: CrossAccountRequirementExtras;
  accountMeta: CrossAccountAccountRef[];
  framework: string;
}

/**
 * Combined findings view for a cross-account requirement: the requirement
 * detail rendered once and a single findings table querying every
 * contributing account's scan at once. Unlike the cross-provider variant
 * there is no per-provider check labeling — every account shares one check
 * set. Mounts lazily: the accordion unmounts collapsed content, so the
 * combined fetch only fires on expand.
 */
export const CrossAccountRequirementContent = ({
  requirement,
  extras,
  accountMeta,
  framework,
}: CrossAccountRequirementContentProps) => {
  const contributingAccounts = accountMeta.filter(
    (account) => extras.accounts[account.id],
  );

  const scanIds = Array.from(
    new Set(
      contributingAccounts.flatMap(
        (account) => extras.scanIdsByAccount[account.id] ?? [],
      ),
    ),
  );

  return (
    <AggregatedRequirementContent
      requirement={requirement}
      scanIds={scanIds}
      framework={framework}
      emptyMessage="No account scan contributed to this requirement with the current filters."
    />
  );
};
