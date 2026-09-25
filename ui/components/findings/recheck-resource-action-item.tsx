"use client";

import { RefreshCw } from "lucide-react";

import { ActionDropdownItem } from "@/components/shadcn/dropdown";
import { usePartialScanHintStore, usePartialScanStore } from "@/store";
import type { PartialScanTarget } from "@/types/partial-scans";

import { usePartialScanTarget } from "./use-partial-scan-target";

export const RECHECK_RESOURCE_LABEL = "Re-check resource";

interface RecheckResourceActionItemProps {
  target: Partial<PartialScanTarget> | null | undefined;
}

/** Prowler Cloud only: opens the partial-scan confirmation for one resource. */
export const RecheckResourceActionItem = ({
  target,
}: RecheckResourceActionItemProps) => {
  const resolvedTarget = usePartialScanTarget(target);
  const openPartialScan = usePartialScanStore((state) => state.openPartialScan);
  const markHintSeen = usePartialScanHintStore(
    (state) => state.markRecheckHintSeen,
  );

  if (!resolvedTarget) return null;

  return (
    <ActionDropdownItem
      icon={<RefreshCw className="size-5" />}
      label={RECHECK_RESOURCE_LABEL}
      aria-label={RECHECK_RESOURCE_LABEL}
      onSelect={() => {
        // Using the menu counts as discovering the feature: the row icon calms.
        markHintSeen();
        openPartialScan(resolvedTarget);
      }}
    />
  );
};
