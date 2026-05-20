"use client";

import { Upload } from "lucide-react";
import { usePathname, useRouter, useSearchParams } from "next/navigation";
import { type ReactNode, useState } from "react";

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
import { CloudFeatureBadgeLink } from "@/components/shared/cloud-feature-badge";
import { EntityInfo } from "@/components/ui/entities";
import type { ProviderType, ScanProviderInfo } from "@/types";
import { PROVIDER_DISPLAY_NAMES, PROVIDER_TYPES } from "@/types/providers";

import { ImportFindingsModal } from "./import-findings-modal";
import { LaunchScanModal } from "./launch-scan-modal";
import {
  getEnabledScanJobsTab,
  getScanJobsTab,
  SCAN_JOBS_TAB,
  SCAN_TAB_LABELS,
  type ScanJobsTab,
} from "./scans-table.utils";

interface ScansPageShellProps {
  providers: ScanProviderInfo[];
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

export function ScansPageShell({
  providers,
  hasManageScansPermission,
  children,
}: ScansPageShellProps) {
  const pathname = usePathname();
  const router = useRouter();
  const searchParams = useSearchParams();
  const [launchOpen, setLaunchOpen] = useState(false);
  const [importOpen, setImportOpen] = useState(false);
  const [importedTabTooltipOpen, setImportedTabTooltipOpen] = useState(false);
  const isCloudEnvironment = process.env.NEXT_PUBLIC_IS_CLOUD_ENV === "true";
  const activeTab = getEnabledScanJobsTab(
    getScanJobsTab(searchParams.get("tab") ?? undefined),
    isCloudEnvironment,
  );
  const providerType = getFirstFilterValue(
    searchParams.get("filter[provider_type__in]"),
  );
  const accountUid = getFirstFilterValue(
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

  const launchDisabled = !hasManageScansPermission || providers.length === 0;
  const importDisabled = !isCloudEnvironment;

  const importButton = (
    <Button
      type="button"
      variant="outline"
      size="lg"
      onClick={() => {
        if (!importDisabled) setImportOpen(true);
      }}
      disabled={importDisabled}
      className="justify-start"
    >
      <Upload className="size-4" />
      Import Findings
    </Button>
  );

  return (
    <div className="flex flex-col gap-[18px]">
      <div className="flex flex-wrap items-center gap-3">
        <div className="grid w-full grid-cols-1 gap-3 md:grid-cols-3 lg:w-auto lg:grid-cols-[240px_240px_240px]">
          <Select
            value={providerType}
            onValueChange={(value) =>
              updateParams({ "filter[provider_type__in]": value })
            }
          >
            <SelectTrigger aria-label="All Providers">
              <SelectValue placeholder="All Providers" />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value={ALL_VALUE}>All Providers</SelectItem>
              {PROVIDER_TYPES.map((provider) => (
                <SelectItem key={provider} value={provider}>
                  {PROVIDER_DISPLAY_NAMES[provider]}
                </SelectItem>
              ))}
            </SelectContent>
          </Select>

          <Select
            value={accountUid}
            onValueChange={(value) =>
              updateParams({ "filter[provider_uid__in]": value })
            }
          >
            <SelectTrigger aria-label="All Accounts">
              <SelectValue placeholder="All Accounts" />
            </SelectTrigger>
            <SelectContent width="wide">
              <SelectItem value={ALL_VALUE}>All Accounts</SelectItem>
              {providers.map((provider) => (
                <SelectItem key={provider.providerId} value={provider.uid}>
                  <EntityInfo
                    cloudProvider={provider.providerType as ProviderType}
                    entityAlias={provider.alias}
                    entityId={provider.uid}
                    showCopyAction={false}
                  />
                </SelectItem>
              ))}
            </SelectContent>
          </Select>

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
          {importDisabled ? (
            <span className="relative inline-flex w-fit sm:mr-14" tabIndex={0}>
              {importButton}
              <span className="absolute top-0 right-0 z-10 translate-x-1/3 -translate-y-1/2">
                <CloudFeatureBadgeLink />
              </span>
            </span>
          ) : (
            importButton
          )}
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

      <ImportFindingsModal open={importOpen} onOpenChange={setImportOpen} />
      <LaunchScanModal
        open={launchOpen}
        onOpenChange={setLaunchOpen}
        providers={providers}
      />
    </div>
  );
}
