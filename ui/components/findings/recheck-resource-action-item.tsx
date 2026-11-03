"use client";

import { RefreshCw } from "lucide-react";

import { ActionDropdownItem } from "@/components/shadcn/dropdown";
import { usePartialScanTarget } from "@/hooks/use-partial-scan-target";
import { usePartialScanStore } from "@/store";
import type { PartialScanTarget } from "@/types/partial-scans";

export const RECHECK_RESOURCE_LABEL = "Re-check resource";

interface RecheckResourceActionItemProps {
  target: Partial<PartialScanTarget> | null | undefined;
  disabledReason?: string;
}

/** Prowler Cloud only: opens the partial-scan confirmation for one resource. */
export const RecheckResourceActionItem = ({
  target,
  disabledReason,
}: RecheckResourceActionItemProps) => {
  const resolvedTarget = usePartialScanTarget(target);
  const openPartialScan = usePartialScanStore((state) => state.openPartialScan);

  if (!resolvedTarget) return null;

  return (
    <ActionDropdownItem
      icon={<RefreshCw className="size-5" />}
      label={RECHECK_RESOURCE_LABEL}
      aria-label={RECHECK_RESOURCE_LABEL}
      disabled={Boolean(disabledReason)}
      disabledTooltip={disabledReason}
      onSelect={() => {
        if (!disabledReason) openPartialScan(resolvedTarget);
      }}
    />
  );
};
