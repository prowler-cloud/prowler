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
} from "@/components/shadcn";
import type { ProviderProps } from "@/types/providers";

import { LaunchScanModal } from "./launch-scan-modal";
import {
  getScanJobsTab,
  getScanTriggerFilterOptions,
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
  const isCloudEnvironment = process.env.NEXT_PUBLIC_IS_CLOUD_ENV === "true";
  const activeTab = getScanJobsTab(searchParams.get("tab") ?? undefined);
  const triggerFilterOptions = getScanTriggerFilterOptions(isCloudEnvironment);
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
          {Object.values(SCAN_JOBS_TAB).map((tab) => (
            <TabsTrigger key={tab} value={tab}>
              {SCAN_TAB_LABELS[tab as ScanJobsTab]}
            </TabsTrigger>
          ))}
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
