"use client";

import { usePathname, useRouter, useSearchParams } from "next/navigation";
import { type ReactNode, useState } from "react";

import { AccountsSelector } from "@/app/(prowler)/_overview/_components/accounts-selector";
import { ProviderTypeSelector } from "@/app/(prowler)/_overview/_components/provider-type-selector";
import {
  Button,
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
  Tabs,
  TabsContent,
  TabsList,
  TabsTrigger,
  Tooltip,
  TooltipContent,
  TooltipTrigger,
} from "@/components/shadcn";
import type { ProviderProps } from "@/types/providers";

import { LaunchScanModal } from "./launch-scan-modal";
import {
  getEnabledScanJobsTab,
  getScanJobsTab,
  SCAN_JOBS_TAB,
  SCAN_TAB_LABELS,
  type ScanJobsTab,
} from "./scans-table.utils";

interface ScansPageShellProps {
  providers: ProviderProps[];
  hasManageScansPermission: boolean;
  children: ReactNode;
}

const ALL_VALUE = "all";

const SCHEDULE_TYPE_OPTIONS = [
  { value: ALL_VALUE, label: "All Scheduled Types" },
  { value: "manual", label: "Single" },
  { value: "scheduled", label: "Scheduled" },
] as const;

function getFirstFilterValue(value: string | null): string {
  return value?.split(",")[0] || ALL_VALUE;
}

function getFilterValues(value: string | null): string[] {
  return value?.split(",").filter(Boolean) ?? [];
}

export function ScansPageShell({
  providers,
  hasManageScansPermission,
  children,
}: ScansPageShellProps) {
  const pathname = usePathname();
  const router = useRouter();
  const searchParams = useSearchParams();
  const [launchOpen, setLaunchOpen] = useState(false);
  const [importedTabTooltipOpen, setImportedTabTooltipOpen] = useState(false);
  const isCloudEnvironment = process.env.NEXT_PUBLIC_IS_CLOUD_ENV === "true";
  const activeTab = getEnabledScanJobsTab(
    getScanJobsTab(searchParams.get("tab") ?? undefined),
    isCloudEnvironment,
  );
  const selectedProviderTypes = getFilterValues(
    searchParams.get("filter[provider_type__in]"),
  );
  const selectedProviderUids = getFilterValues(
    searchParams.get("filter[provider_uid__in]"),
  );
  const scheduleType = getFirstFilterValue(searchParams.get("filter[trigger]"));

  const updateParams = (updates: Record<string, string | null>) => {
    const params = new URLSearchParams(searchParams.toString());

    Object.entries(updates).forEach(([key, value]) => {
      if (!value || value === ALL_VALUE) params.delete(key);
      else params.set(key, value);
    });

    params.delete("page");
    params.delete("scanId");
    router.push(`${pathname}?${params.toString()}`, { scroll: false });
  };

  const setTab = (tab: string) => {
    if (tab === SCAN_JOBS_TAB.IMPORTED && !isCloudEnvironment) return;

    updateParams({ tab });
  };

  const setFilterValues = (filterKey: string, values: string[]) => {
    updateParams({
      [`filter[${filterKey}]`]: values.length > 0 ? values.join(",") : null,
    });
  };

  const launchDisabled = !hasManageScansPermission || providers.length === 0;

  return (
    <div className="flex flex-col gap-[18px]">
      <div className="flex flex-wrap items-center gap-3">
        <div className="grid w-full grid-cols-1 gap-3 md:grid-cols-3 lg:w-auto lg:grid-cols-[240px_240px_240px]">
          <ProviderTypeSelector
            providers={providers}
            onBatchChange={setFilterValues}
            selectedValues={selectedProviderTypes}
          />

          <AccountsSelector
            providers={providers}
            filterKey="provider_uid__in"
            onBatchChange={setFilterValues}
            selectedValues={selectedProviderUids}
            selectedProviderTypes={selectedProviderTypes}
          />

          <Select
            value={scheduleType}
            onValueChange={(value) =>
              updateParams({ "filter[trigger]": value })
            }
          >
            <SelectTrigger aria-label="All Scheduled Types">
              <SelectValue placeholder="All Scheduled Types" />
            </SelectTrigger>
            <SelectContent>
              {SCHEDULE_TYPE_OPTIONS.map((option) => (
                <SelectItem key={option.value} value={option.value}>
                  {option.label}
                </SelectItem>
              ))}
            </SelectContent>
          </Select>
        </div>

        <div className="flex flex-col gap-3 sm:flex-row sm:items-center">
          <Button
            type="button"
            size="lg"
            onClick={() => setLaunchOpen(true)}
            disabled={launchDisabled}
          >
            Launch Scan
          </Button>
        </div>
      </div>

      <Tabs
        value={activeTab}
        onValueChange={setTab}
        className="flex flex-col gap-[18px]"
      >
        <TabsList className="overflow-x-auto">
          {Object.values(SCAN_JOBS_TAB).map((tab) => {
            const isImportedTab = tab === SCAN_JOBS_TAB.IMPORTED;
            const isDisabled = isImportedTab && !isCloudEnvironment;
            const trigger = (
              <TabsTrigger
                key={tab}
                value={tab}
                aria-disabled={isDisabled}
                data-disabled={isDisabled ? "" : undefined}
                className={isDisabled ? "cursor-not-allowed opacity-50" : ""}
                onMouseEnter={() => {
                  if (isDisabled) setImportedTabTooltipOpen(true);
                }}
                onMouseLeave={() => {
                  if (isDisabled) setImportedTabTooltipOpen(false);
                }}
                onFocus={() => {
                  if (isDisabled) setImportedTabTooltipOpen(true);
                }}
                onBlur={() => {
                  if (isDisabled) setImportedTabTooltipOpen(false);
                }}
              >
                {SCAN_TAB_LABELS[tab as ScanJobsTab]}
              </TabsTrigger>
            );

            if (!isDisabled) return trigger;

            return (
              <Tooltip key={tab} open={importedTabTooltipOpen}>
                <TooltipTrigger asChild>{trigger}</TooltipTrigger>
                <TooltipContent side="top">
                  Available in Prowler Cloud
                </TooltipContent>
              </Tooltip>
            );
          })}
        </TabsList>
        <TabsContent value={activeTab} className="mt-0">
          {children}
        </TabsContent>
      </Tabs>

      <LaunchScanModal
        open={launchOpen}
        onOpenChange={setLaunchOpen}
        providers={providers}
      />
    </div>
  );
}
