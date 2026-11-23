"use client";

import { Lock } from "lucide-react";

import { Button } from "@/components/shadcn/button/button";
import { FINDINGS_PREVIEW_ROW_LIMIT } from "@/lib/findings-access";
import { useCloudUpgradeStore } from "@/store";
import { PAID_PLAN_UPGRADE_FEATURE } from "@/types/cloud-upgrade";

interface FindingsPreviewLockProps {
  totalCount?: number;
}

// Floats over the blurred rows of a locked /findings table.
export function FindingsPreviewLock({ totalCount }: FindingsPreviewLockProps) {
  const openCloudUpgrade = useCloudUpgradeStore(
    (state) => state.openCloudUpgrade,
  );
  const scope =
    totalCount !== undefined
      ? `of ${totalCount.toLocaleString()} finding groups`
      : "finding groups";

  return (
    <div
      role="region"
      aria-label="Findings preview"
      className="bg-bg-neutral-secondary border-border-neutral-secondary flex w-full max-w-md flex-col items-center gap-3 rounded-2xl border p-6 text-center shadow-lg"
    >
      <div className="bg-bg-neutral-tertiary text-text-neutral-primary flex size-10 items-center justify-center rounded-xl">
        <Lock aria-hidden="true" className="size-5" />
      </div>
      <p className="text-text-neutral-primary text-sm font-semibold">
        Showing the {FINDINGS_PREVIEW_ROW_LIMIT} most critical {scope}
      </p>
      <p className="text-text-neutral-secondary text-sm">
        Upgrade to unlock the full list, pagination, and every affected
        resource.
      </p>
      <Button
        type="button"
        onClick={(event) =>
          openCloudUpgrade(
            PAID_PLAN_UPGRADE_FEATURE.FINDINGS_PREVIEW,
            event.currentTarget,
          )
        }
      >
        Unlock All Findings
      </Button>
    </div>
  );
}
