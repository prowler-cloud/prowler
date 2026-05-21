"use client";

import { ExternalLink, Info } from "lucide-react";
import Link from "next/link";

import { Alert, AlertDescription, AlertTitle } from "@/components/shadcn";
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
const IMPORT_FINDINGS_DOCS_URL =
  "https://docs.prowler.com/user-guide/tutorials/prowler-app-import-findings";

function ImportedScansEmptyState() {
  return (
    <div className="border-border-neutral-secondary bg-bg-neutral-secondary rounded-large flex min-h-[280px] flex-col items-center justify-center gap-4 border p-6 text-center">
      <h2 className="text-text-neutral-primary text-sm font-semibold">
        There are no scans with imported findings yet
      </h2>
      <p className="text-text-neutral-secondary mt-2 max-w-md text-sm">
        Scans with imported findings will appear here when available.
      </p>
      <Alert variant="info" className="max-w-xl text-left">
        <Info />
        <AlertTitle>Import findings documentation</AlertTitle>
        <AlertDescription>
          <span>
            Review the{" "}
            <Link
              href={IMPORT_FINDINGS_DOCS_URL}
              target="_blank"
              rel="noreferrer"
              className="inline-flex items-center gap-1 font-medium underline underline-offset-2"
            >
              Import Findings guide
              <ExternalLink className="size-3" />
            </Link>{" "}
            for supported files and ingestion steps.
          </span>
        </AlertDescription>
      </Alert>
    </div>
  );
}

export function ScanJobsTable({ data, meta, tab }: ScanJobsTableProps) {
  const hasRefreshingScan = data.some((scan) =>
    REFRESHING_STATES.includes(
      scan.attributes.state as (typeof REFRESHING_STATES)[number],
    ),
  );
  const columns = getScanJobsColumns({ tab });

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
      />
    </>
  );
}
