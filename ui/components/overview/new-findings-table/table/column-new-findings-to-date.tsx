"use client";

import { ColumnDef } from "@tanstack/react-table";
import { useSearchParams } from "next/navigation";

import { DataTableRowDetails } from "@/components/findings/table";
import { InfoIcon } from "@/components/icons";
import { DateWithTime } from "@/components/ui/entities";
import { TriggerSheet } from "@/components/ui/sheet";
import { SeverityBadge, StatusFindingBadge } from "@/components/ui/table";
import { FindingProps } from "@/types";

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

export const ColumnNewFindingsToDate: ColumnDef<FindingProps>[] = [
  {
    id: "moreInfo",
    header: "Details",
    cell: ({ row }) => {
      const searchParams = useSearchParams();
      const findingId = searchParams.get("id");
      const isOpen = findingId === row.original.id;
      return (
        <div className="flex justify-center">
          <TriggerSheet
            triggerComponent={<InfoIcon className="text-primary" size={16} />}
            title="Finding Details"
            description="View the finding details"
            defaultOpen={isOpen}
          >
            <DataTableRowDetails
              entityId={row.original.id}
              findingDetails={row.original}
            />
          </TriggerSheet>
        </div>
      );
    },
  },
  {
    accessorKey: "check",
    header: "Finding",
    cell: ({ row }) => {
      const { checktitle } = getFindingsMetadata(row);
      return (
        <p className="max-w-[450px] whitespace-normal break-words text-small">
          {checktitle}
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

      return <StatusFindingBadge size="sm" status={status} />;
    },
  },
  {
    accessorKey: "updated_at",
    header: "Last seen",
    cell: ({ row }) => {
      const {
        attributes: { updated_at },
      } = getFindingsData(row);
      return (
        <div className="w-[100px]">
          <DateWithTime dateTime={updated_at} />
        </div>
      );
    },
  },
  {
    accessorKey: "region",
    header: "Region",
    cell: ({ row }) => {
      const region = getResourceData(row, "region");

      return (
        <div className="w-[80px]">
          {typeof region === "string" ? region : "Invalid region"}
        </div>
      );
    },
  },
  {
    accessorKey: "service",
    header: "Service",
    cell: ({ row }) => {
      const { servicename } = getFindingsMetadata(row);
      return <p className="max-w-96 truncate text-small">{servicename}</p>;
    },
  },
  {
    accessorKey: "account",
    header: "Account",
    cell: ({ row }) => {
      const account = getProviderData(row, "uid");

      return (
        <>
          <p className="max-w-96 truncate text-small">
            {typeof account === "string" ? account : "Invalid account"}
          </p>
        </>
      );
    },
  },
];
