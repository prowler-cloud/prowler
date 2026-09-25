"use client";

import { RefreshCw } from "lucide-react";

import { ActionDropdownItem } from "@/components/shadcn/dropdown";
import { useAuth } from "@/hooks/use-auth";
import {
  isPartialScanAvailable,
  isPartialScanTarget,
} from "@/lib/partial-scans";
import { isCloud } from "@/lib/shared/env";
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
  const { hasPermission } = useAuth();
  const openPartialScan = usePartialScanStore((state) => state.openPartialScan);

  const isAvailable = isPartialScanAvailable({
    cloudEnabled: isCloud(),
    canManageScans: hasPermission("manage_scans"),
  });
  if (!isAvailable || !isPartialScanTarget(target)) return null;

  return (
    <ActionDropdownItem
      icon={<RefreshCw className="size-5" />}
      label={RECHECK_RESOURCE_LABEL}
      aria-label={RECHECK_RESOURCE_LABEL}
      onSelect={() => openPartialScan(target)}
    />
  );
};
