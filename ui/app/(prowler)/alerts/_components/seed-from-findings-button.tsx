"use client";

import { BellPlusIcon } from "lucide-react";
import Link from "next/link";
import { useRouter } from "next/navigation";
import { useState } from "react";

import { createAlert } from "@/app/(prowler)/alerts/_actions";
import { AlertFormModal } from "@/app/(prowler)/alerts/_components/alert-form-modal";
import { toAlertPayload } from "@/app/(prowler)/alerts/_lib/alert-adapter";
import {
  canSeedAlertFromFindingsFilters,
  toPortableAlertFilterBag,
} from "@/app/(prowler)/alerts/_lib/seeding";
import {
  ALERT_TRIGGER_KINDS,
  type AlertCondition,
  type AlertsFilterBag,
} from "@/app/(prowler)/alerts/_types";
import type {
  AlertFormSubmitResult,
  AlertFormValues,
} from "@/app/(prowler)/alerts/_types/alert-form";
import { buildFindingsFilterChips } from "@/components/findings/findings-filters.utils";
import {
  Button,
  Tooltip,
  TooltipContent,
  TooltipTrigger,
} from "@/components/shadcn";
import { ToastAction, useToast } from "@/components/ui";
import type { ScanEntity } from "@/types";
import type { ProviderProps } from "@/types/providers";

const DISABLED_FILTER_TOOLTIP =
  "Apply at least one Findings filter to create an alert from filters.";

interface SeedFromFindingsButtonProps {
  filterBag: AlertsFilterBag;
  providers?: ProviderProps[];
  scans?: Array<{ [scanId: string]: ScanEntity }>;
  uniqueRegions?: string[];
  uniqueServices?: string[];
  uniqueResourceTypes?: string[];
  uniqueCategories?: string[];
  uniqueGroups?: string[];
  className?: string;
  size?: "sm" | "default";
  defaultName?: string;
}

const toChipFilterMap = (
  filterBag: AlertsFilterBag,
): Record<string, string[]> =>
  Object.fromEntries(
    Object.entries(filterBag)
      .filter(([key]) => key.startsWith("filter["))
      .map(([key, value]) => [
        key,
        (Array.isArray(value) ? value : value.split(","))
          .map((entry) => entry.trim())
          .filter(Boolean),
      ])
      .filter(([, values]) => values.length > 0),
  );

export const SeedFromFindingsButton = ({
  filterBag,
  providers = [],
  scans = [],
  uniqueRegions = [],
  uniqueServices = [],
  uniqueResourceTypes = [],
  uniqueCategories = [],
  uniqueGroups = [],
  className,
  size = "sm",
  defaultName = "Findings filter alert",
}: SeedFromFindingsButtonProps) => {
  const router = useRouter();
  const { toast } = useToast();
  const [modalOpen, setModalOpen] = useState(false);

  const canSeedFromFilters = canSeedAlertFromFindingsFilters(filterBag);
  const portableFilterBag = toPortableAlertFilterBag(filterBag);
  const selectedFindingsFilterChips = buildFindingsFilterChips(
    toChipFilterMap(filterBag),
    { providers, scans, includeMuted: true },
  );

  const handleClick = () => {
    if (!canSeedFromFilters) return;
    setModalOpen(true);
  };

  const submitAlert = async (
    values: AlertFormValues,
    advancedCondition: AlertCondition | null,
  ): Promise<AlertFormSubmitResult> => {
    const result = await createAlert(toAlertPayload(values, advancedCondition));
    if (!result.ok) return { ok: false, error: result.error.detail };
    toast({
      title: "Alert created",
      description: result.data.data.attributes.name,
      action: (
        <ToastAction altText="View alerts" asChild>
          <Link href="/alerts">View Alerts</Link>
        </ToastAction>
      ),
    });
    router.refresh();
    return { ok: true, alertId: result.data.data.id };
  };

  const button = (
    <Button
      size={size}
      variant="default"
      onClick={handleClick}
      disabled={!canSeedFromFilters}
      className={className}
    >
      <BellPlusIcon size={14} />
      Create Alert
    </Button>
  );

  if (canSeedFromFilters) {
    return (
      <>
        {button}
        <AlertFormModal
          open={modalOpen}
          defaultFrequency={ALERT_TRIGGER_KINDS.AFTER_SCAN}
          providers={providers}
          uniqueRegions={uniqueRegions}
          uniqueServices={uniqueServices}
          uniqueResourceTypes={uniqueResourceTypes}
          uniqueCategories={uniqueCategories}
          uniqueGroups={uniqueGroups}
          initialFindingsFilters={portableFilterBag}
          selectedFindingsFilterChips={selectedFindingsFilterChips}
          defaultName={defaultName}
          onOpenChange={setModalOpen}
          onSubmit={submitAlert}
        />
      </>
    );
  }

  return (
    <Tooltip>
      <TooltipTrigger asChild>
        <span
          className="inline-flex"
          tabIndex={0}
          title={DISABLED_FILTER_TOOLTIP}
        >
          {button}
        </span>
      </TooltipTrigger>
      <TooltipContent side="top" className="max-w-xs">
        {DISABLED_FILTER_TOOLTIP}
      </TooltipContent>
    </Tooltip>
  );
};
