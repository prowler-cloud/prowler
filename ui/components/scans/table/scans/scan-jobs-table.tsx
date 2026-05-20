"use client";

import type { RowSelectionState } from "@tanstack/react-table";
import { useState } from "react";

import { DataTable } from "@/components/ui/table";
import type { MetaDataProps, ScanProps } from "@/types";

import { AutoRefresh } from "../../auto-refresh";
import { SCAN_JOBS_TAB, type ScanJobsTab } from "../../scans-table.utils";
import { getScanJobsColumns } from "./scan-jobs-columns";

interface ScanJobsTableProps {
  data: ScanProps[];
  meta?: MetaDataProps;
  tab: ScanJobsTab;
}

const REFRESHING_STATES = ["available", "executing"] as const;

function ImportedScansEmptyState() {
  return (
    <div className="border-border-neutral-secondary bg-bg-neutral-secondary rounded-large flex min-h-[280px] flex-col items-center justify-center border p-6 text-center">
      <h2 className="text-text-neutral-primary text-sm font-semibold">
        No imported scans yet
      </h2>
      <p className="text-text-neutral-secondary mt-2 max-w-md text-sm">
        Imported Prowler CLI findings will appear here when available.
      </p>
    </div>
  );
}

export function ScanJobsTable({ data, meta, tab }: ScanJobsTableProps) {
  const [rowSelection, setRowSelection] = useState<RowSelectionState>({});
  const hasRefreshingScan = data.some((scan) =>
    REFRESHING_STATES.includes(
      scan.attributes.state as (typeof REFRESHING_STATES)[number],
    ),
  );
  const columns = getScanJobsColumns({
    tab,
    rowSelection,
    selectableRowCount: data.length,
  });

  if (tab === SCAN_JOBS_TAB.IMPORTED && data.length === 0) {
    return <ImportedScansEmptyState />;
  }

  return (
    <>
      <AutoRefresh hasExecutingScan={hasRefreshingScan} />
      <DataTable
        key={`scan-jobs-${tab}-${data.length}-${meta?.pagination?.page ?? 1}`}
        columns={columns}
        data={data}
        metadata={meta}
        enableRowSelection
        rowSelection={rowSelection}
        onRowSelectionChange={setRowSelection}
      />
    </>
  );
}
