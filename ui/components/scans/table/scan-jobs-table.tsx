"use client";

import { useSearchParams } from "next/navigation";

import { LighthouseContextContributor } from "@/components/lighthouse/context-contributor";
import { DataTable } from "@/components/shadcn/table";
import {
  buildScanContext,
  buildScanSummaryContext,
} from "@/lib/lighthouse/context/contributions";
import type { MetaDataProps, ScanJobsTab, ScanProps } from "@/types";
import { SCAN_JOBS_TAB } from "@/types";
import type { ScanScheduleCapability } from "@/types/schedules";

import { AutoRefresh } from "../auto-refresh";
import { NoScansEmptyState } from "../no-scans-empty-state";

import { getScanJobsColumns } from "./scan-jobs-columns";

interface ScanJobsTableProps {
  data: ScanProps[];
  meta?: MetaDataProps;
  tab: ScanJobsTab;
  hasFilters?: boolean;
  scanScheduleCapability?: ScanScheduleCapability;
}

const REFRESHING_STATES = ["available", "executing"] as const;

export function ScanJobsTable({
  data,
  meta,
  tab,
  hasFilters = false,
  scanScheduleCapability,
}: ScanJobsTableProps) {
  const searchParams = useSearchParams();
  const hasRefreshingScan = data.some((scan) =>
    REFRESHING_STATES.includes(
      scan.attributes.state as (typeof REFRESHING_STATES)[number],
    ),
  );
  const columns = getScanJobsColumns({
    tab,
    capability: scanScheduleCapability,
  });
  const showEmptyState = data.length === 0 && !hasFilters;
  const selectedScanId = searchParams?.get("scanId");
  const selectedScan = selectedScanId
    ? data.find((scan) => scan.id === selectedScanId)
    : undefined;

  return (
    <>
      {meta?.pagination.count !== undefined && (
        <LighthouseContextContributor
          key={`scans-summary-${tab}-${meta.pagination.count}`}
          contributorId="scans-summary"
          item={buildScanSummaryContext(meta.pagination.count, tab)}
        />
      )}
      {selectedScan && (
        <LighthouseContextContributor
          key={`scan-${selectedScan.id}-${selectedScan.attributes.state}`}
          contributorId={`scan-${selectedScan.id}`}
          item={buildScanContext({
            id: selectedScan.id,
            state: selectedScan.attributes.state,
            providerUid: selectedScan.providerInfo?.uid,
          })}
        />
      )}
      <AutoRefresh hasExecutingScan={hasRefreshingScan} />
      {showEmptyState ? (
        <NoScansEmptyState tab={tab} />
      ) : (
        <DataTable
          key={`scan-jobs-${tab}-${meta?.pagination?.page ?? 1}`}
          columns={columns}
          data={data}
          metadata={meta}
          // Anchor the view-first-scan tour's "in-progress" step to the first row of
          // the active (In Progress) tab; absent on other tabs so the tour only points
          // at a running scan.
          getRowAttributes={(row) =>
            row.index === 0 && tab === SCAN_JOBS_TAB.ACTIVE
              ? { "data-tour-id": "view-first-scan-in-progress" }
              : {}
          }
        />
      )}
    </>
  );
}
