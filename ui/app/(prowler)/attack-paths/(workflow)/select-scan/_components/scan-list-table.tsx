"use client";

import { useRouter } from "next/navigation";

import { Button } from "@/components/shadcn/button/button";
import { DateWithTime } from "@/components/ui/entities/date-with-time";
import { EntityInfoShort } from "@/components/ui/entities/entity-info-short";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import type { ProviderType } from "@/types";
import type { AttackPathScan } from "@/types/attack-paths";
import { SCAN_STATES } from "@/types/attack-paths";

import { ScanStatusBadge } from "./scan-status-badge";

interface ScanListTableProps {
  scans: AttackPathScan[];
}

const TABLE_COLUMN_COUNT = 6;

/**
 * Table displaying AWS account attack path scans
 * Shows scan metadata and allows selection of completed scans
 */
export const ScanListTable = ({ scans }: ScanListTableProps) => {
  const router = useRouter();

  const handleSelectScan = (scanId: string) => {
    router.push(`/attack-paths/query-builder?scanId=${scanId}`);
  };

  const isSelectDisabled = (scan: AttackPathScan) => {
    return scan.attributes.state !== SCAN_STATES.COMPLETED;
  };

  const getSelectButtonLabel = (scan: AttackPathScan) => {
    if (scan.attributes.state === SCAN_STATES.EXECUTING) {
      return "Waiting...";
    }
    if (scan.attributes.state === SCAN_STATES.FAILED) {
      return "Failed";
    }
    return "Select";
  };

  return (
    <>
      <div className="minimal-scrollbar rounded-large shadow-small border-border-neutral-secondary bg-bg-neutral-secondary relative z-0 flex w-full flex-col gap-4 overflow-auto border p-4">
        <Table aria-label="Attack path scans table listing provider accounts, scan dates, status, progress, and duration">
          <TableHeader>
            <TableRow>
              <TableHead>Provider / Account</TableHead>
              <TableHead>Last Scan Date</TableHead>
              <TableHead>Status</TableHead>
              <TableHead>Progress</TableHead>
              <TableHead>Duration</TableHead>
              <TableHead className="text-right">Action</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {scans.length === 0 ? (
              <TableRow>
                <TableCell
                  colSpan={TABLE_COLUMN_COUNT}
                  className="h-24 text-center"
                >
                  No attack path scans available.
                </TableCell>
              </TableRow>
            ) : (
              scans.map((scan) => {
                const isDisabled = isSelectDisabled(scan);
                const duration = scan.attributes.duration
                  ? `${Math.floor(scan.attributes.duration / 60)}m ${scan.attributes.duration % 60}s`
                  : "-";

                return (
                  <TableRow key={scan.id}>
                    <TableCell className="font-medium">
                      <EntityInfoShort
                        cloudProvider={
                          scan.attributes.provider_type as ProviderType
                        }
                        entityAlias={scan.attributes.provider_alias}
                        entityId={scan.attributes.provider_uid}
                      />
                    </TableCell>
                    <TableCell>
                      {scan.attributes.completed_at ? (
                        <DateWithTime
                          inline
                          dateTime={scan.attributes.completed_at}
                        />
                      ) : (
                        "-"
                      )}
                    </TableCell>
                    <TableCell>
                      <ScanStatusBadge
                        status={scan.attributes.state}
                        progress={scan.attributes.progress}
                      />
                    </TableCell>
                    <TableCell>
                      <span className="text-sm">
                        {scan.attributes.progress}%
                      </span>
                    </TableCell>
                    <TableCell>
                      <span className="text-sm">{duration}</span>
                    </TableCell>
                    <TableCell className="text-right">
                      <Button
                        type="button"
                        aria-label="Select scan"
                        disabled={isDisabled}
                        variant={isDisabled ? "secondary" : "default"}
                        onClick={() => handleSelectScan(scan.id)}
                        className="w-full max-w-24"
                      >
                        {getSelectButtonLabel(scan)}
                      </Button>
                    </TableCell>
                  </TableRow>
                );
              })
            )}
          </TableBody>
        </Table>
      </div>
      <p className="text-xs text-gray-500 dark:text-gray-400">
        Only attack path scans with &quot;Completed&quot; status can be
        selected. Scans in progress will update automatically.
      </p>
    </>
  );
};
