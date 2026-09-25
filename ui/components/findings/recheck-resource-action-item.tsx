"use client";

import { RefreshCw } from "lucide-react";

import { ActionDropdownItem } from "@/components/shadcn/dropdown";
import { usePartialScanTarget } from "@/hooks/use-partial-scan-target";
import { usePartialScanStore } from "@/store";
import type { PartialScanTarget } from "@/types/partial-scans";

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

  if (!resolvedTarget) return null;

  return (
    <ActionDropdownItem
      icon={<RefreshCw className="size-5" />}
      label={RECHECK_RESOURCE_LABEL}
      aria-label={RECHECK_RESOURCE_LABEL}
      onSelect={() => openPartialScan(resolvedTarget)}
    />
  );
};
