"use client";

import { useSearchParams } from "next/navigation";
import { type ReactNode, useState } from "react";

import { MutedFindingsConfigButton } from "@/components/providers/muted-findings-config-button";
import {
  Button,
  Tabs,
  TabsContent,
  TabsList,
  TabsTrigger,
} from "@/components/shadcn";
import {
  LAUNCH_SCAN_SEARCH_PARAM,
  LAUNCH_SCAN_SEARCH_VALUE,
} from "@/lib/scans-navigation";
import { useScansStore } from "@/store";
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
  const searchParams = useSearchParams();
  const [urlLaunchOpen, setUrlLaunchOpen] = useState(
    () =>
      searchParams.get(LAUNCH_SCAN_SEARCH_PARAM) === LAUNCH_SCAN_SEARCH_VALUE,
  );
  const isLaunchScanModalOpen = useScansStore(
    (state) => state.isLaunchScanModalOpen,
  );
  const setLaunchScanModalOpen = useScansStore(
    (state) => state.setLaunchScanModalOpen,
  );
  const filters = useScansFilters();
  const hasConnectedProviders = providers.some(
    (provider) => provider.attributes.connection.connected === true,
  );
  const launchDisabled = !hasManageScansPermission || !hasConnectedProviders;
  const launchOpen = isLaunchScanModalOpen || urlLaunchOpen;

  const handleLaunchOpenChange = (open: boolean) => {
    setLaunchScanModalOpen(open);
    if (!open) setUrlLaunchOpen(false);
  };

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
          scheduleType={filters.scheduleType}
          scanStatus={filters.scanStatus}
          showStatusFilter={filters.showStatusFilter}
          onScheduleTypeChange={filters.setScheduleType}
          onScanStatusChange={filters.setScanStatus}
        />

        <Button
          type="button"
          size="lg"
          onClick={() => handleLaunchOpenChange(true)}
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
        onOpenChange={handleLaunchOpenChange}
        providers={providers}
      />
    </div>
  );
}
