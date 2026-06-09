"use client";

import { ProviderAccountSelectors } from "@/components/filters/provider-account-selectors";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/shadcn";
import { SCAN_JOBS_TAB, type ScanJobsTab } from "@/types";
import type { ProviderProps } from "@/types/providers";

import {
  getScanStatusFilterOptions,
  getScanTriggerFilterOptions,
} from "./scans.utils";

interface ScansFilterBarProps {
  providers: ProviderProps[];
  activeTab: ScanJobsTab;
  scheduleType: string;
  scanStatus: string;
  showStatusFilter: boolean;
  onScheduleTypeChange: (value: string) => void;
  onScanStatusChange: (value: string) => void;
}

const filterItemClass = "w-full md:w-[calc(50%-0.375rem)] xl:w-60";

export function ScansFilterBar({
  providers,
  activeTab,
  scheduleType,
  scanStatus,
  showStatusFilter,
  onScheduleTypeChange,
  onScanStatusChange,
}: ScansFilterBarProps) {
  const isCloudEnvironment = process.env.NEXT_PUBLIC_IS_CLOUD_ENV === "true";
  const triggerFilterOptions = getScanTriggerFilterOptions(isCloudEnvironment);
  const statusFilterOptions = getScanStatusFilterOptions(activeTab);
  const showScheduleTypeFilter = activeTab !== SCAN_JOBS_TAB.SCHEDULED;

  return (
    <>
      <ProviderAccountSelectors
        providers={providers}
        accountFilterKey="provider_uid__in"
        accountValue="uid"
        paramsToDeleteOnChange={["page", "scanId"]}
        providerSelectorClassName={filterItemClass}
        accountSelectorClassName={filterItemClass}
      />

      {showScheduleTypeFilter && (
        <Select value={scheduleType} onValueChange={onScheduleTypeChange}>
          <SelectTrigger aria-label="All Types" className={filterItemClass}>
            <SelectValue placeholder="All Types" />
          </SelectTrigger>
          <SelectContent>
            {triggerFilterOptions.map((option) => (
              <SelectItem key={option.value} value={option.value}>
                {option.label}
              </SelectItem>
            ))}
          </SelectContent>
        </Select>
      )}

      {showStatusFilter && (
        <Select value={scanStatus} onValueChange={onScanStatusChange}>
          <SelectTrigger aria-label="All Statuses" className={filterItemClass}>
            <SelectValue placeholder="All Statuses" />
          </SelectTrigger>
          <SelectContent>
            {statusFilterOptions.map((option) => (
              <SelectItem key={option.value} value={option.value}>
                {option.label}
              </SelectItem>
            ))}
          </SelectContent>
        </Select>
      )}
    </>
  );
}
