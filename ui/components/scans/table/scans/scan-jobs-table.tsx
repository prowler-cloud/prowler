"use client";

import { DataTable } from "@/components/ui/table";
import type { MetaDataProps, ScanProps } from "@/types";

import { AutoRefresh } from "../../auto-refresh";
import { type ScanJobsTab } from "../../scans-table.utils";
import { getScanJobsColumns } from "./scan-jobs-columns";

interface ScanJobsTableProps {
  data: ScanProps[];
  meta?: MetaDataProps;
  tab: ScanJobsTab;
}

const REFRESHING_STATES = ["available", "executing"] as const;

export function ScanJobsTable({ data, meta, tab }: ScanJobsTableProps) {
  const hasRefreshingScan = data.some((scan) =>
    REFRESHING_STATES.includes(
      scan.attributes.state as (typeof REFRESHING_STATES)[number],
    ),
  );
  const columns = getScanJobsColumns({ tab });

  return (
    <>
      <AutoRefresh hasExecutingScan={hasRefreshingScan} />
      <DataTable
        key={`scan-jobs-${tab}-${data.length}-${meta?.pagination?.page ?? 1}`}
        columns={columns}
        data={data}
        metadata={meta}
      />
    </>
  );
}
