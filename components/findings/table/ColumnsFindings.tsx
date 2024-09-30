"use client";

import {
  Button,
  Dropdown,
  DropdownItem,
  DropdownMenu,
  DropdownTrigger,
} from "@nextui-org/react";
import { ColumnDef } from "@tanstack/react-table";

import { VerticalDotsIcon } from "@/components/icons";
import { SeverityBadge, StatusBadge } from "@/components/ui/table";
import { FindingProps } from "@/types";

const getFindingsAttributes = (row: { original: FindingProps }) => {
  return row.original.attributes;
};

export const ColumnsFindings: ColumnDef<FindingProps>[] = [
  {
    accessorKey: "checkTitle",
    header: "Check",
    cell: ({ row }) => {
      const { CheckTitle } = getFindingsAttributes(row);
      return <p className="text-sm">{CheckTitle}</p>;
    },
  },
  {
    accessorKey: "severity",
    header: "Severity",
    cell: ({ row }) => {
      const { severity } = getFindingsAttributes(row);
      return <SeverityBadge severity={severity} />;
    },
  },
  {
    accessorKey: "status",
    header: "Status",
    cell: ({ row }) => {
      const { status } = getFindingsAttributes(row);
      return <StatusBadge status={status} />;
    },
  },
  {
    accessorKey: "region",
    header: "Region",
    cell: ({ row }) => {
      const { region } = getFindingsAttributes(row);
      return <p className="text-sm text-nowrap">{region}</p>;
    },
  },
  {
    accessorKey: "service",
    header: "Service",
    cell: ({ row }) => {
      const { service } = getFindingsAttributes(row);
      return <p className="text-sm">{service}</p>;
    },
  },
  {
    accessorKey: "account",
    header: "Account",
    cell: ({ row }) => {
      const { account } = getFindingsAttributes(row);
      return <p className="text-sm">{account}</p>;
    },
  },
  {
    accessorKey: "actions",
    header: () => (
      <div className="relative flex justify-end items-center gap-2">
        <Dropdown className="bg-background border-1 border-default-200">
          <DropdownTrigger>
            <Button isIconOnly radius="full" size="sm" variant="light">
              <VerticalDotsIcon className="text-default-400" />
            </Button>
          </DropdownTrigger>
          <DropdownMenu>
            <DropdownItem>Mute Findings for Selected Filters</DropdownItem>
            <DropdownItem>Configure Muted Findings</DropdownItem>
          </DropdownMenu>
        </Dropdown>
      </div>
    ),
  },
];
