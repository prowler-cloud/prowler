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
import { DateWithTime } from "@/components/providers";
import { StatusBadge } from "@/components/ui";
import { UserProps } from "@/types";

const getUserData = (row: { original: UserProps }) => {
  return row.original;
};

export const ColumnsUser: ColumnDef<UserProps>[] = [
  {
    accessorKey: "email",
    header: "Email",
    cell: ({ row }) => {
      const { email } = getUserData(row);
      return <p className="font-semibold">{email}</p>;
    },
  },
  {
    accessorKey: "name",
    header: "Name",
    cell: ({ row }) => {
      const { name } = getUserData(row);
      return <p className="font-semibold">{name}</p>;
    },
  },
  {
    accessorKey: "role",
    header: "Role",
    cell: ({ row }) => {
      const { role } = getUserData(row);
      return <p className="font-semibold">{role}</p>;
    },
  },
  {
    accessorKey: "added",
    header: "Added",
    cell: ({ row }) => {
      const { dateAdded } = getUserData(row);
      return <DateWithTime dateTime={dateAdded} showTime={false} />;
    },
  },
  {
    accessorKey: "status",
    header: "Status",
    cell: ({ row }) => {
      const { status } = getUserData(row);
      return <StatusBadge status={status} />;
    },
  },
  {
    accessorKey: "actions",
    header: () => <div className="text-right">Actions</div>,
    id: "actions",
    cell: () => {
      return (
        <div className="relative flex justify-end items-center gap-2">
          <Dropdown className="bg-background border-1 border-default-200">
            <DropdownTrigger>
              <Button isIconOnly radius="full" size="sm" variant="light">
                <VerticalDotsIcon className="text-default-400" />
              </Button>
            </DropdownTrigger>
            <DropdownMenu>
              <DropdownItem>Edit</DropdownItem>
            </DropdownMenu>
          </Dropdown>
        </div>
      );
    },
  },
];
