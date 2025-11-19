"use client";

import { Spacer } from "@heroui/spacer";
import {
  Table,
  TableBody,
  TableCell,
  TableColumn,
  TableHeader,
  TableRow,
} from "@heroui/table";
import { useRouter } from "next/navigation";

import { CustomButton } from "@/components/ui/custom";
import { DateWithTime } from "@/components/ui/entities/date-with-time";
import type { AttackPathScan } from "@/types/attack-paths";
import { SCAN_STATES } from "@/types/attack-paths";

import { ScanStatusBadge } from "./scan-status-badge";

interface ScanListTableProps {
  scans: AttackPathScan[];
}

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
    <div className="flex flex-col gap-4">
      <Table aria-label="Attack path scans table" shadow="sm">
        <TableHeader>
          <TableColumn>Provider / Account</TableColumn>
          <TableColumn>Last Scan Date</TableColumn>
          <TableColumn>Status</TableColumn>
          <TableColumn>Progress</TableColumn>
          <TableColumn>Duration</TableColumn>
          <TableColumn align="end">Action</TableColumn>
        </TableHeader>
        <TableBody emptyContent="No attack path scans available.">
          {scans.map((scan) => {
            const isDisabled = isSelectDisabled(scan);
            const duration = scan.attributes.duration
              ? `${Math.floor(scan.attributes.duration / 60)}m ${scan.attributes.duration % 60}s`
              : "-";

            return (
              <TableRow key={scan.id}>
                <TableCell className="font-medium">
                  <div className="flex flex-col gap-1">
                    <span>{scan.attributes.provider_alias}</span>
                    <span className="text-xs text-gray-500 dark:text-gray-400">
                      ID: {scan.id.substring(0, 8)}...
                    </span>
                  </div>
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
                  <span className="text-sm">{scan.attributes.progress}%</span>
                </TableCell>
                <TableCell>
                  <span className="text-sm">{duration}</span>
                </TableCell>
                <TableCell>
                  <div className="flex justify-end">
                    <CustomButton
                      type="button"
                      ariaLabel="Select scan"
                      isDisabled={isDisabled}
                      color={isDisabled ? "secondary" : "action"}
                      variant="solid"
                      onPress={() => handleSelectScan(scan.id)}
                      className="w-full max-w-24"
                    >
                      {getSelectButtonLabel(scan)}
                    </CustomButton>
                  </div>
                </TableCell>
              </TableRow>
            );
          })}
        </TableBody>
      </Table>
      <Spacer y={4} />
      <p className="text-xs text-gray-500 dark:text-gray-400">
        Only attack path scans with &quot;Completed&quot; status can be
        selected. Scans in progress will update automatically.
      </p>
    </div>
  );
};
