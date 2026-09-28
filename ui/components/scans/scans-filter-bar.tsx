"use client";

import { ProviderAccountSelectors } from "@/components/filters/provider-account-selectors";
import { ProviderGroupSelector } from "@/components/filters/provider-group-selector";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/shadcn";
import { isCloud } from "@/lib/shared/env";
import { SCAN_JOBS_TAB, type ScanJobsTab } from "@/types";
import type { ProviderGroup } from "@/types/components";
import { FILTER_FIELD } from "@/types/filters";
import type { ProviderProps } from "@/types/providers";

import {
  getScanStatusFilterOptions,
  getScanTriggerFilterOptions,
} from "./scans.utils";

interface ScansFilterBarProps {
  providers: ProviderProps[];
  providerGroups?: ProviderGroup[];
  activeTab: ScanJobsTab;
  scheduleType: string;
  scanStatus: string;
  showStatusFilter: boolean;
  onScheduleTypeChange: (value: string) => void;
  onScanStatusChange: (value: string) => void;
}

const filterItemClass = "w-full sm:max-w-[240px] sm:min-w-[180px] sm:flex-1";

export function ScansFilterBar({
  providers,
  providerGroups = [],
  activeTab,
  scheduleType,
  scanStatus,
  showStatusFilter,
  onScheduleTypeChange,
  onScanStatusChange,
}: ScansFilterBarProps) {
  const isCloudEnvironment = isCloud();
  const triggerFilterOptions = getScanTriggerFilterOptions(isCloudEnvironment);
  const statusFilterOptions = getScanStatusFilterOptions(activeTab);
  const showScheduleTypeFilter = activeTab !== SCAN_JOBS_TAB.SCHEDULED;

  return (
    <>
      <ProviderAccountSelectors
        providers={providers}
        accountFilterKey={FILTER_FIELD.PROVIDER}
        accountValue="id"
        paramsToDeleteOnChange={["page", "scanId"]}
        providerSelectorClassName={filterItemClass}
        accountSelectorClassName={filterItemClass}
      />

      <div className={filterItemClass}>
        <ProviderGroupSelector
          groups={providerGroups}
          paramsToDeleteOnChange={["page", "scanId"]}
        />
      </div>

      {showScheduleTypeFilter && (
        <div className={filterItemClass}>
          <Select value={scheduleType} onValueChange={onScheduleTypeChange}>
            <SelectTrigger aria-label="All Types">
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
        </div>
      )}

      {showStatusFilter && (
        <div className={filterItemClass}>
          <Select value={scanStatus} onValueChange={onScanStatusChange}>
            <SelectTrigger aria-label="All Statuses">
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
        </div>
      )}
    </>
  );
}
