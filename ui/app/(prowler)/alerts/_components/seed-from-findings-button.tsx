"use client";

import { BellPlusIcon } from "lucide-react";
import Link from "next/link";
import { useRouter } from "next/navigation";
import { useState } from "react";

import { createAlert, seedAlertRule } from "@/app/(prowler)/alerts/_actions";
import { AlertFormModal } from "@/app/(prowler)/alerts/_components/alert-form-modal";
import {
  getFindingsFiltersFromAlertCondition,
  toAlertPayload,
} from "@/app/(prowler)/alerts/_lib/alert-adapter";
import {
  ALERT_SEVERITY_VALUES,
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
import { ToastAction, useToast } from "@/components/shadcn";
import { CloudFeatureBadgeLink } from "@/components/shared/cloud-feature-badge";
import type { ScanEntity } from "@/types";
import type { ProviderProps } from "@/types/providers";

const DISABLED_FILTER_TOOLTIP =
  "Apply at least one Findings filter to create an alert from filters.";
const ALERT_SEED_ERROR = "Apply at least one alert-compatible Findings filter.";

const NON_FILTER_QUERY_KEYS = new Set(["sort", "page", "pageSize"]);
const ALERT_COMPATIBLE_FILTER_KEYS = new Set([
  "filter[provider_type__in]",
  "filter[provider_id__in]",
  "filter[severity__in]",
  "filter[delta]",
  "filter[region__in]",
  "filter[service__in]",
  "filter[resource_type__in]",
  "filter[category__in]",
  "filter[resource_groups__in]",
  "filter[check_id__in]",
  "filter[finding_group_id]",
  "filter[resource_uid__in]",
]);

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
  size?: "sm" | "default" | "lg";
  defaultName?: string;
  isCloudEnabled?: boolean;
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

const hasFindingFilterValue = (filterBag: AlertsFilterBag): boolean =>
  Object.entries(filterBag).some(([rawKey, value]) => {
    if (!rawKey.startsWith("filter[") || NON_FILTER_QUERY_KEYS.has(rawKey)) {
      return false;
    }

    const values = Array.isArray(value) ? value : [value];
    return values.some((entry) =>
      entry
        .split(",")
        .map((part) => part.trim())
        .some(Boolean),
    );
  });

const hasAlertCompatibleFilterValue = (filterBag: AlertsFilterBag): boolean =>
  Object.entries(filterBag).some(([rawKey, value]) => {
    if (!ALERT_COMPATIBLE_FILTER_KEYS.has(rawKey)) return false;

    const values = Array.isArray(value) ? value : [value];
    return values.some((entry) =>
      entry
        .split(",")
        .map((part) => part.trim())
        .some(Boolean),
    );
  });

const withDefaultAlertSeedFilters = (
  filterBag: AlertsFilterBag,
): AlertsFilterBag => {
  if (hasAlertCompatibleFilterValue(filterBag)) return filterBag;

  return {
    ...filterBag,
    "filter[severity__in]": [...ALERT_SEVERITY_VALUES],
  };
};

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
  size = "lg",
  defaultName = "Findings filter alert",
  isCloudEnabled = true,
}: SeedFromFindingsButtonProps) => {
  const router = useRouter();
  const { toast } = useToast();
  const [modalOpen, setModalOpen] = useState(false);
  const [seeding, setSeeding] = useState(false);
  const [seededCondition, setSeededCondition] = useState<AlertCondition | null>(
    null,
  );
  const [selectedFindingsFilterChips, setSelectedFindingsFilterChips] =
    useState(() =>
      buildFindingsFilterChips(toChipFilterMap(filterBag), {
        providers,
        scans,
      }),
    );

  const canSeedFromFilters = hasFindingFilterValue(filterBag);

  const handleClick = async () => {
    if (!isCloudEnabled || !canSeedFromFilters) return;
    setSeeding(true);
    const result = await seedAlertRule(withDefaultAlertSeedFilters(filterBag));
    setSeeding(false);
    if (result?.error) {
      toast({
        variant: "destructive",
        title: "Alert seed failed",
        description: ALERT_SEED_ERROR,
      });
      return;
    }

    const condition = result.data.attributes.condition as AlertCondition;
    setSeededCondition(condition);
    setSelectedFindingsFilterChips(
      buildFindingsFilterChips(
        getFindingsFiltersFromAlertCondition(condition),
        { providers, scans },
      ),
    );
    setModalOpen(true);
  };

  const submitAlert = async (
    values: AlertFormValues,
  ): Promise<AlertFormSubmitResult> => {
    const result = await createAlert(toAlertPayload(values));
    if (result?.error) return { ok: false, error: result.error };
    toast({
      title: "Alert created",
      description: result.data.attributes.name,
      action: (
        <ToastAction altText="View alerts" asChild>
          <Link href="/alerts">View Alerts</Link>
        </ToastAction>
      ),
    });
    router.refresh();
    return { ok: true, alertId: result.data.id };
  };

  const button = (
    <Button
      size={size}
      variant="default"
      onClick={handleClick}
      disabled={!isCloudEnabled || !canSeedFromFilters || seeding}
      className={className}
    >
      <BellPlusIcon size={14} />
      {seeding ? "Preparing Alert" : "Create Alert"}
    </Button>
  );

  if (isCloudEnabled && canSeedFromFilters) {
    return (
      <>
        {button}
        {seededCondition && (
          <AlertFormModal
            open={modalOpen}
            defaultFrequency={ALERT_TRIGGER_KINDS.AFTER_SCAN}
            providers={providers}
            uniqueRegions={uniqueRegions}
            uniqueServices={uniqueServices}
            uniqueResourceTypes={uniqueResourceTypes}
            uniqueCategories={uniqueCategories}
            uniqueGroups={uniqueGroups}
            seededCondition={seededCondition}
            selectedFindingsFilterChips={selectedFindingsFilterChips}
            defaultName={defaultName}
            onOpenChange={setModalOpen}
            onSubmit={submitAlert}
          />
        )}
      </>
    );
  }

  if (!isCloudEnabled) {
    return (
      <span className="relative inline-flex" tabIndex={0}>
        {button}
        <span className="absolute top-0 right-0 z-10 translate-x-1/3 -translate-y-1/2">
          <CloudFeatureBadgeLink />
        </span>
      </span>
    );
  }

  return (
    <Tooltip>
      <TooltipTrigger asChild>
        <span className="relative inline-flex" tabIndex={0}>
          {button}
        </span>
      </TooltipTrigger>
      <TooltipContent side="top" className="max-w-xs">
        {DISABLED_FILTER_TOOLTIP}
      </TooltipContent>
    </Tooltip>
  );
};
