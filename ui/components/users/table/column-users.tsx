"use client";

import { ColumnDef } from "@tanstack/react-table";

import { DateWithTime } from "@/components/ui/entities";
import { DataTableColumnHeader } from "@/components/ui/table";
import { UserProps } from "@/types";

import { DataTableRowActions } from "./data-table-row-actions";

const getUserData = (row: { original: UserProps }) => {
  return row.original.attributes;
};

export const ColumnsUser: ColumnDef<UserProps>[] = [
  {
    accessorKey: "name",
    header: ({ column }) => (
      <DataTableColumnHeader column={column} title={"Name"} param="name" />
    ),
    cell: ({ row }) => {
      const data = getUserData(row);
      return <p className="font-semibold">{data?.name || "N/A"}</p>;
    },
  },
  {
    accessorKey: "email",
    header: ({ column }) => (
      <DataTableColumnHeader column={column} title={"Email"} param="email" />
    ),
    cell: ({ row }) => {
      const { email } = getUserData(row);
      return <p className="font-semibold">{email}</p>;
    },
  },
  {
    accessorKey: "role",
    header: () => <div className="text-left">Role</div>,
    cell: ({ row }) => {
      const { role } = getUserData(row);
      return <p className="font-semibold">{role?.name || "No Role"}</p>;
    },
  },
  {
    accessorKey: "company_name",
    header: ({ column }) => (
      <DataTableColumnHeader
        column={column}
        title={"Company name"}
        param="company_name"
      />
    ),
    cell: ({ row }) => {
      const { company_name } = getUserData(row);
      return <p className="font-semibold">{company_name}</p>;
    },
  },
  {
    accessorKey: "date_joined",
    header: ({ column }) => (
      <DataTableColumnHeader
        column={column}
        title={"Joined"}
        param="date_joined"
      />
    ),
    cell: ({ row }) => {
      const { date_joined } = getUserData(row);
      return <DateWithTime dateTime={date_joined} showTime={false} />;
    },
  },

  {
    accessorKey: "actions",
    header: () => <div className="text-right">Actions</div>,
    id: "actions",
    cell: ({ row }) => {
      const roles = row.original.roles;
      return <DataTableRowActions row={row} roles={roles} />;
    },
  },
];
