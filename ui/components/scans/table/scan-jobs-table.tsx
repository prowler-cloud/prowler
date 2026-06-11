"use client";

import { DataTable } from "@/components/shadcn/table";
import type { MetaDataProps, ScanJobsTab, ScanProps } from "@/types";

import { AutoRefresh } from "../auto-refresh";
import { NoScansEmptyState } from "../no-scans-empty-state";
import { getScanJobsColumns } from "./scan-jobs-columns";

interface ScanJobsTableProps {
  data: ScanProps[];
  meta?: MetaDataProps;
  tab: ScanJobsTab;
  hasFilters?: boolean;
}

const REFRESHING_STATES = ["available", "executing"] as const;

export function ScanJobsTable({
  data,
  meta,
  tab,
  hasFilters = false,
}: ScanJobsTableProps) {
  const hasRefreshingScan = data.some((scan) =>
    REFRESHING_STATES.includes(
      scan.attributes.state as (typeof REFRESHING_STATES)[number],
    ),
  );
  const columns = getScanJobsColumns({ tab });
  const showEmptyState = data.length === 0 && !hasFilters;

  return (
    <>
      <AutoRefresh hasExecutingScan={hasRefreshingScan} />
      {showEmptyState ? (
        <NoScansEmptyState tab={tab} />
      ) : (
        <DataTable
          key={`scan-jobs-${tab}-${meta?.pagination?.page ?? 1}`}
          columns={columns}
          data={data}
          metadata={meta}
        />
      )}
    </>
  );
}
