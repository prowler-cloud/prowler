"use client";

import { usePathname, useRouter, useSearchParams } from "next/navigation";

import { getScanJobsTab } from "@/components/scans/scans.utils";
import { SCAN_JOBS_TAB, type ScanJobsTab } from "@/types";

const ALL_VALUE = "all";

function getFirstFilterValue(value: string | null): string {
  return value?.split(",")[0] || ALL_VALUE;
}

export interface UseScansFiltersReturn {
  activeTab: ScanJobsTab;
  scheduleType: string;
  scanStatus: string;
  showStatusFilter: boolean;
  setTab: (tab: string) => void;
  setScheduleType: (value: string) => void;
  setScanStatus: (value: string) => void;
}

export function useScansFilters(): UseScansFiltersReturn {
  const pathname = usePathname();
  const router = useRouter();
  const searchParams = useSearchParams();

  const activeTab = getScanJobsTab(searchParams.get("tab") ?? undefined);
  const showStatusFilter = activeTab === SCAN_JOBS_TAB.COMPLETED;
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

  const setScheduleType = (value: string) =>
    updateParams({ "filter[trigger]": value });

  const setScanStatus = (value: string) =>
    updateParams({ "filter[state]": null, "filter[state__in]": value });

  return {
    activeTab,
    scheduleType,
    scanStatus,
    showStatusFilter,
    setTab,
    setScheduleType,
    setScanStatus,
  };
}
