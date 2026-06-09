"use client";

import { usePathname, useSearchParams } from "next/navigation";
import { type ReactNode, Suspense, useState } from "react";

import { OnboardingTrigger, PageReady } from "@/components/onboarding";
import { MutedFindingsConfigButton } from "@/components/providers/muted-findings-config-button";
import {
  Button,
  Tabs,
  TabsContent,
  TabsList,
  TabsTrigger,
} from "@/components/shadcn";
import { getFlowById } from "@/lib/onboarding";
import {
  LAUNCH_SCAN_SEARCH_PARAM,
  LAUNCH_SCAN_SEARCH_VALUE,
} from "@/lib/scans-navigation";
import { useScansStore } from "@/store";
import { SCAN_JOBS_TAB, SCAN_TAB_LABELS, type ScanJobsTab } from "@/types";
import type { ProviderProps } from "@/types/providers";

const viewFirstScanFlow = getFlowById("view-first-scan")!;

import { CliImportBanner } from "./cli-import-banner";
import { LaunchScanModal } from "./launch-scan-modal";
import { ScansFilterBar } from "./scans-filter-bar";
import { useScansFilters } from "./use-scans-filters";

interface ScansPageShellProps {
  providers: ProviderProps[];
  hasManageScansPermission: boolean;
  activeScanCount?: number;
  children: ReactNode;
}

export function ScansPageShell({
  providers,
  hasManageScansPermission,
  activeScanCount = 0,
  children,
}: ScansPageShellProps) {
  const pathname = usePathname();
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
  const isCloudEnvironment = process.env.NEXT_PUBLIC_IS_CLOUD_ENV === "true";
  const launchDisabled = !hasManageScansPermission || !hasConnectedProviders;
  const launchOpen = isLaunchScanModalOpen || urlLaunchOpen;

  const getTabLabel = (tab: ScanJobsTab) => {
    const label = SCAN_TAB_LABELS[tab];
    if (tab !== SCAN_JOBS_TAB.ACTIVE) return label;

    return `${label} (${activeScanCount})`;
  };

  const handleLaunchOpenChange = (open: boolean) => {
    setLaunchScanModalOpen(open);
    if (open) return;
    setUrlLaunchOpen(false);
    // Remove ?launchScan via History API (not router.replace) to avoid an RSC
    // refetch that reloads the page; revalidatePath in scanOnDemand already
    // refreshes the scans list when a scan is launched.
    if (!searchParams.has(LAUNCH_SCAN_SEARCH_PARAM)) return;
    const params = new URLSearchParams(searchParams.toString());
    params.delete(LAUNCH_SCAN_SEARCH_PARAM);
    const query = params.toString();
    window.history.replaceState(
      null,
      "",
      query ? `${pathname}?${query}` : pathname,
    );
  };

  return (
    <div className="flex flex-col gap-[18px]">
      {/* Suspense required: OnboardingTrigger reads useSearchParams */}
      <Suspense fallback={null}>
        <OnboardingTrigger flow={viewFirstScanFlow} />
      </Suspense>
      {/* Signals the navbar that this route's data has loaded (enables the replay icon). */}
      <PageReady />
      <div
        role="group"
        aria-label="Scan filters and actions"
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
          data-tour-id="view-first-scan-launch"
        >
          Launch Scan
        </Button>
      </div>

      {isCloudEnvironment && <CliImportBanner />}

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
          <TabsList
            className="overflow-x-auto"
            data-tour-id="view-first-scan-tabs"
          >
            {Object.values(SCAN_JOBS_TAB).map((tab) => (
              <TabsTrigger key={tab} value={tab}>
                {getTabLabel(tab as ScanJobsTab)}
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
