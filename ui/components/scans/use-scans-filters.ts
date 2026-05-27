"use client";

import { usePathname, useRouter, useSearchParams } from "next/navigation";

import { getScanJobsTab } from "@/components/scans/scans.utils";
import { SCAN_JOBS_TAB, type ScanJobsTab } from "@/types";

const ALL_VALUE = "all";

function getFirstFilterValue(value: string | null): string {
  return value?.split(",")[0] || ALL_VALUE;
}

function getFilterValues(value: string | null): string[] {
  return value?.split(",").filter(Boolean) ?? [];
}

export interface UseScansFiltersReturn {
  activeTab: ScanJobsTab;
  selectedProviderTypes: string[];
  selectedProviderUids: string[];
  scheduleType: string;
  scanStatus: string;
  showStatusFilter: boolean;
  setTab: (tab: string) => void;
  setFilterValues: (filterKey: string, values: string[]) => void;
  setScheduleType: (value: string) => void;
  setScanStatus: (value: string) => void;
}

export function useScansFilters(): UseScansFiltersReturn {
  const pathname = usePathname();
  const router = useRouter();
  const searchParams = useSearchParams();

  const activeTab = getScanJobsTab(searchParams.get("tab") ?? undefined);
  const showStatusFilter = activeTab === SCAN_JOBS_TAB.COMPLETED;
  const selectedProviderTypes = getFilterValues(
    searchParams.get("filter[provider_type__in]"),
  );
  const selectedProviderUids = getFilterValues(
    searchParams.get("filter[provider_uid__in]"),
  );
  const scheduleType = getFirstFilterValue(searchParams.get("filter[trigger]"));
  const scanStatus = getFirstFilterValue(
    searchParams.get("filter[state__in]") ?? searchParams.get("filter[state]"),
  );

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

  const setTab = (tab: string) =>
    updateParams({
      tab,
      sort: null,
      "filter[state]": null,
      "filter[state__in]": null,
    });

  const setFilterValues = (filterKey: string, values: string[]) =>
    updateParams({
      [`filter[${filterKey}]`]: values.length > 0 ? values.join(",") : null,
    });

  const setScheduleType = (value: string) =>
    updateParams({ "filter[trigger]": value });

  const setScanStatus = (value: string) =>
    updateParams({ "filter[state]": null, "filter[state__in]": value });

  return {
    activeTab,
    selectedProviderTypes,
    selectedProviderUids,
    scheduleType,
    scanStatus,
    showStatusFilter,
    setTab,
    setFilterValues,
    setScheduleType,
    setScanStatus,
  };
}
