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
import { FindingsProps } from "@/types";

const getFindingsAttributes = (row: { original: FindingsProps }) => {
  return row.original.attributes;
};

export const ColumnsFindings: ColumnDef<FindingsProps>[] = [
  {
    accessorKey: "checkTitle",
    header: "Check",
    cell: ({ row }) => {
      const { CheckTitle } = getFindingsAttributes(row);
      return <p className="text-medium">{CheckTitle}</p>;
    },
  },
  {
    accessorKey: "severity",
    header: "Severity",
    cell: ({ row }) => {
      const { severity } = getFindingsAttributes(row);
      return <p className="text-medium">{severity}</p>;
    },
  },
  {
    accessorKey: "status",
    header: "Status",
    cell: ({ row }) => {
      const { status } = getFindingsAttributes(row);
      return <p className="text-medium">{status}</p>;
    },
  },
  {
    accessorKey: "region",
    header: "Region",
    cell: ({ row }) => {
      const { region } = getFindingsAttributes(row);
      return <p className="text-medium">{region}</p>;
    },
  },
  {
    accessorKey: "service",
    header: "Service",
    cell: ({ row }) => {
      const { service } = getFindingsAttributes(row);
      return <p className="text-medium">{service}</p>;
    },
  },
  {
    accessorKey: "account",
    header: "Account",
    cell: ({ row }) => {
      const { account } = getFindingsAttributes(row);
      return <p className="text-medium">{account}</p>;
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
