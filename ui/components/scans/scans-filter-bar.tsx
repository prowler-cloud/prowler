"use client";

import { AccountsSelector } from "@/app/(prowler)/_overview/_components/accounts-selector";
import { ProviderTypeSelector } from "@/app/(prowler)/_overview/_components/provider-type-selector";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/shadcn";
import type { ScanJobsTab } from "@/types";
import type { ProviderProps } from "@/types/providers";

import {
  getScanStatusFilterOptions,
  getScanTriggerFilterOptions,
} from "./scans-table.utils";

interface ScansFilterBarProps {
  providers: ProviderProps[];
  activeTab: ScanJobsTab;
  selectedProviderTypes: string[];
  selectedProviderUids: string[];
  scheduleType: string;
  scanStatus: string;
  showStatusFilter: boolean;
  onFilterChange: (filterKey: string, values: string[]) => void;
  onScheduleTypeChange: (value: string) => void;
  onScanStatusChange: (value: string) => void;
}

export function ScansFilterBar({
  providers,
  activeTab,
  selectedProviderTypes,
  selectedProviderUids,
  scheduleType,
  scanStatus,
  showStatusFilter,
  onFilterChange,
  onScheduleTypeChange,
  onScanStatusChange,
}: ScansFilterBarProps) {
  const isCloudEnvironment = process.env.NEXT_PUBLIC_IS_CLOUD_ENV === "true";
  const triggerFilterOptions = getScanTriggerFilterOptions(isCloudEnvironment);
  const statusFilterOptions = getScanStatusFilterOptions(activeTab);

  return (
    <div className="grid w-full grid-cols-1 gap-3 md:grid-cols-2 xl:w-auto xl:grid-cols-[240px_240px_240px_240px]">
      <ProviderTypeSelector
        providers={providers}
        onBatchChange={onFilterChange}
        selectedValues={selectedProviderTypes}
      />

      <AccountsSelector
        providers={providers}
        filterKey="provider_uid__in"
        onBatchChange={onFilterChange}
        selectedValues={selectedProviderUids}
        selectedProviderTypes={selectedProviderTypes}
      />

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

      {showStatusFilter && (
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
      )}
    </div>
  );
}
