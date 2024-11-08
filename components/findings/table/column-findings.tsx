"use client";

import { ColumnDef } from "@tanstack/react-table";

import { SeverityBadge, Status, StatusBadge } from "@/components/ui/table";
import { FindingProps } from "@/types";
import { TriggerSheet } from "@/components/ui/sheet";
import { DataTableRowActions } from "./data-table-row-actions";
import { PlusIcon } from "@/components/icons";
import { DataTableRowDetails } from "@/components/findings/table";

const statusMap: Record<"PASS" | "FAIL" | "MANUAL" | "MUTED", Status> = {
  PASS: "completed",
  FAIL: "failed",
  MANUAL: "completed",
  MUTED: "cancelled",
};

const getFindingsData = (row: { original: FindingProps }) => {
  return row.original;
};

const getFindingsMetadata = (row: { original: FindingProps }) => {
  return row.original.attributes.check_metadata;
};

const getResourceData = (
  row: { original: FindingProps },
  field: keyof FindingProps["relationships"]["resource"]["attributes"],
) => {
  return (
    row.original.relationships?.resource?.attributes?.[field] ||
    `No ${field} found in resource`
  );
};

const getProviderData = (
  row: { original: FindingProps },
  field: keyof FindingProps["relationships"]["provider"]["attributes"],
) => {
  return (
    row.original.relationships?.provider?.attributes?.[field] ||
    `No ${field} found in provider`
  );
};

const getScanData = (
  row: { original: FindingProps },
  field: keyof FindingProps["relationships"]["scan"]["attributes"],
) => {
  return (
    row.original.relationships?.scan?.attributes?.[field] ||
    `No ${field} found in scan`
  );
};

export const ColumnFindings: ColumnDef<FindingProps>[] = [
  {
    accessorKey: "check",
    header: "Check",
    cell: ({ row }) => {
      const { checktitle } = getFindingsMetadata(row);
      return <p className="max-w-96 truncate text-medium">{checktitle}</p>;
    },
  },
  {
    accessorKey: "scanName",
    header: "Scan Name",
    cell: ({ row }) => {
      const name = getScanData(row, "name");

      return (
        <p className="max-w-96 truncate text-medium">
          {typeof name === "string" || typeof name === "number"
            ? name
            : "Invalid data"}
        </p>
      );
    },
  },
  {
    accessorKey: "severity",
    header: "Severity",
    cell: ({ row }) => {
      const {
        attributes: { severity },
      } = getFindingsData(row);
      return <SeverityBadge severity={severity} />;
    },
  },
  {
    accessorKey: "status",
    header: "Status",
    cell: ({ row }) => {
      const {
        attributes: { status },
      } = getFindingsData(row);

      const mappedStatus = statusMap[status];

      return <StatusBadge status={mappedStatus} />;
    },
  },
  {
    accessorKey: "region",
    header: "Region",
    cell: ({ row }) => {
      const region = getResourceData(row, "region");

      return (
        <>
          <div>{typeof region === "string" ? region : "Invalid region"}</div>
        </>
      );
    },
  },
  {
    accessorKey: "service",
    header: "Service",
    cell: ({ row }) => {
      const { servicename } = getFindingsMetadata(row);
      return <p className="max-w-96 truncate text-medium">{servicename}</p>;
    },
  },
  {
    accessorKey: "account",
    header: "Account",
    cell: ({ row }) => {
      const account = getProviderData(row, "uid");

      return (
        <>
          <div>{typeof account === "string" ? account : "Invalid account"}</div>
        </>
      );
    },
  },
  {
    id: "moreInfo",
    header: "Details",
    cell: ({ row }) => {
      return (
        <TriggerSheet
          triggerComponent={<PlusIcon />}
          title="Finding Details"
          description="View the finding details"
        >
          <DataTableRowDetails finding={getFindingsData(row)} />
        </TriggerSheet>
      );
    },
  },
  {
    id: "actions",
    cell: ({ row }) => {
      return <DataTableRowActions row={row} />;
    },
  },
];
