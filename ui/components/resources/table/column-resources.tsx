"use client";

import { ColumnDef } from "@tanstack/react-table";
import { useSearchParams } from "next/navigation";

import { InfoIcon } from "@/components/icons";
import { EntityInfoShort } from "@/components/ui/entities";
import { TriggerSheet } from "@/components/ui/sheet";
import { DataTableColumnHeader } from "@/components/ui/table";
import { ResourceProps } from "@/types";

import { DataTableRowDetails } from "./data-table-row-details";

const getResourceData = (
  row: { original: ResourceProps },
  field: keyof ResourceProps["attributes"],
) => {
  return row.original.attributes?.[field] || `No ${field} found in resource`;
};

const getProviderData = (
  row: { original: ResourceProps },
  field: keyof ResourceProps["relationships"]["provider"]["data"]["attributes"],
) => {
  return (
    row.original.relationships?.provider?.data?.attributes?.[field] ??
    `No ${field} found in provider`
  );
};

const ResourceDetailsCell = ({ row }: { row: any }) => {
  const searchParams = useSearchParams();
  const resourceId = searchParams.get("resourceId");
  const isOpen = resourceId === row.original.id;

  return (
    <div className="flex w-9 items-center justify-center">
      <TriggerSheet
        triggerComponent={<InfoIcon className="text-primary" size={16} />}
        title="Resource Details"
        description="View the Resource details"
        defaultOpen={isOpen}
      >
        <DataTableRowDetails
          resourceData={row.original}
          resourceId={row.original.id}
        />
      </TriggerSheet>
    </div>
  );
};

export const ColumnResources: ColumnDef<ResourceProps>[] = [
  {
    id: "moreInfo",
    header: "Details",
    cell: ({ row }) => <ResourceDetailsCell row={row} />,
  },
  {
    accessorKey: "name",
    header: ({ column }) => (
      <DataTableColumnHeader
        column={column}
        title={"Resource Name"}
        param="name"
      />
    ),
    cell: ({ row }) => {
      const resourceName = getResourceData(row, "name");
      return (
        <>
          <div className="w-[120px] whitespace-normal break-words text-xs">
            {typeof resourceName === "string" ? resourceName : "Invalid name"}
          </div>
        </>
      );
    },
  },
  {
    accessorKey: "failedFindings",
    header: "Failed Findings",
    cell: ({ row }) => {
      const count = row.original.relationships.findings.data.filter(
        (data) => data.attributes.status === "FAIL",
      ).length;
      return (
        <>
          <div className="text-xs">{count}</div>
        </>
      );
    },
  },
  {
    accessorKey: "region",
    header: ({ column }) => (
      <DataTableColumnHeader column={column} title={"Region"} param="region" />
    ),
    cell: ({ row }) => {
      const region = getResourceData(row, "region");

      return (
        <div className="w-[80px] text-xs">
          {typeof region === "string" ? region : "Invalid region"}
        </div>
      );
    },
  },
  {
    accessorKey: "type",
    header: ({ column }) => (
      <DataTableColumnHeader column={column} title={"Type"} param="type" />
    ),
    cell: ({ row }) => {
      const type = getResourceData(row, "type");

      return (
        <div className="w-[120px] whitespace-normal break-words text-xs">
          {typeof type === "string" ? type : "Invalid type"}
        </div>
      );
    },
  },
  {
    accessorKey: "service",
    header: ({ column }) => (
      <DataTableColumnHeader
        column={column}
        title={"Service"}
        param="service"
      />
    ),
    cell: ({ row }) => {
      const service = getResourceData(row, "service");

      return (
        <div className="w-[80px] text-xs">
          {typeof service === "string" ? service : "Invalid region"}
        </div>
      );
    },
  },
  {
    accessorKey: "provider",
    header: "Cloud Provider",
    cell: ({ row }) => {
      const provider = getProviderData(row, "provider");
      const alias = getProviderData(row, "alias");
      const uid = getProviderData(row, "uid");
      return (
        <>
          <EntityInfoShort
            cloudProvider={provider as "aws" | "azure" | "gcp" | "kubernetes"}
            entityAlias={alias as string}
            entityId={uid as string}
          />
        </>
      );
    },
  },
];
