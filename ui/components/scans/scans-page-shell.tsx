"use client";

import { type ReactNode, useState } from "react";

import { MutedFindingsConfigButton } from "@/components/providers/muted-findings-config-button";
import {
  Button,
  Tabs,
  TabsContent,
  TabsList,
  TabsTrigger,
} from "@/components/shadcn";
import { SCAN_JOBS_TAB, SCAN_TAB_LABELS, type ScanJobsTab } from "@/types";
import type { ProviderProps } from "@/types/providers";

import { LaunchScanModal } from "./launch-scan-modal";
import { ScansFilterBar } from "./scans-filter-bar";
import { useScansFilters } from "./use-scans-filters";

interface ScansPageShellProps {
  providers: ProviderProps[];
  hasManageScansPermission: boolean;
  children: ReactNode;
}

export function ScansPageShell({
  providers,
  hasManageScansPermission,
  children,
}: ScansPageShellProps) {
  const [launchOpen, setLaunchOpen] = useState(false);
  const filters = useScansFilters();
  const launchDisabled = !hasManageScansPermission || providers.length === 0;

  return (
    <div className="flex flex-col gap-[18px]">
      <div
        role="group"
        aria-label="Scan filters"
        className="flex flex-wrap items-center gap-3"
      >
        <ScansFilterBar
          providers={providers}
          activeTab={filters.activeTab}
          selectedProviderTypes={filters.selectedProviderTypes}
          selectedProviderUids={filters.selectedProviderUids}
          scheduleType={filters.scheduleType}
          scanStatus={filters.scanStatus}
          showStatusFilter={filters.showStatusFilter}
          onFilterChange={filters.setFilterValues}
          onScheduleTypeChange={filters.setScheduleType}
          onScanStatusChange={filters.setScanStatus}
        />

        <Button
          type="button"
          size="lg"
          onClick={() => setLaunchOpen(true)}
          disabled={launchDisabled}
          className="w-full md:w-auto"
        >
          Launch Scan
        </Button>
      </div>

      <Tabs
        value={filters.activeTab}
        onValueChange={filters.setTab}
        className="flex flex-col gap-[18px]"
      >
        <div
          role="group"
          aria-label="Scan tabs"
          className="flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between"
        >
          <TabsList className="overflow-x-auto">
            {Object.values(SCAN_JOBS_TAB).map((tab) => (
              <TabsTrigger key={tab} value={tab}>
                {SCAN_TAB_LABELS[tab as ScanJobsTab]}
              </TabsTrigger>
            ))}
          </TabsList>
          <div className="shrink-0">
            <MutedFindingsConfigButton />
          </div>
        </div>
        <TabsContent value={filters.activeTab} className="mt-0">
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
