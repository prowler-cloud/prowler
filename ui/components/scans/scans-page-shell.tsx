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
} from "@/components/shadcn";
import { EntityInfo } from "@/components/ui/entities";
import type { ProviderType, ScanProviderInfo } from "@/types";
import { PROVIDER_DISPLAY_NAMES, PROVIDER_TYPES } from "@/types/providers";

import { ImportFindingsModal } from "./import-findings-modal";
import { LaunchScanModal } from "./launch-scan-modal";
import {
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
  const activeTab = getScanJobsTab(searchParams.get("tab") ?? undefined);
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
    updateParams({ tab });
  };

  const launchDisabled = !hasManageScansPermission || providers.length === 0;

  return (
    <div className="flex flex-col gap-5">
      <div className="flex flex-col gap-4 lg:flex-row lg:items-center lg:justify-between">
        <div className="grid w-full grid-cols-1 gap-3 md:grid-cols-3 lg:max-w-[760px]">
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

        <div className="flex flex-col gap-3 sm:flex-row sm:items-center lg:justify-end">
          <Button
            type="button"
            variant="link"
            onClick={() => setImportOpen(true)}
            className="justify-start px-0"
          >
            <Upload className="size-4" />
            Import Prowler CLI Findings
          </Button>
          <Button
            type="button"
            onClick={() => setLaunchOpen(true)}
            disabled={launchDisabled}
          >
            Launch Scan
          </Button>
        </div>
      </div>

      <Tabs value={activeTab} onValueChange={setTab}>
        <TabsList className="overflow-x-auto">
          {Object.values(SCAN_JOBS_TAB).map((tab) => (
            <TabsTrigger key={tab} value={tab}>
              {SCAN_TAB_LABELS[tab as ScanJobsTab]}
            </TabsTrigger>
          ))}
        </TabsList>
        <TabsContent value={activeTab}>{children}</TabsContent>
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
