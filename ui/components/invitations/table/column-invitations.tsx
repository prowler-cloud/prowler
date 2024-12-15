"use client";

import { ColumnDef } from "@tanstack/react-table";

import { DateWithTime } from "@/components/ui/entities";
import { DataTableColumnHeader } from "@/components/ui/table";
import { InvitationProps } from "@/types";

import { DataTableRowActions } from "./data-table-row-actions";

const getInvitationData = (row: { original: InvitationProps }) => {
  return row.original.attributes;
};

export const ColumnsInvitation: ColumnDef<InvitationProps>[] = [
  {
    accessorKey: "email",
    header: () => <div className="text-left">Email</div>,
    cell: ({ row }) => {
      const data = getInvitationData(row);
      return <p className="font-semibold">{data?.email || "N/A"}</p>;
    },
  },
  {
    accessorKey: "state",
    header: ({ column }) => (
      <DataTableColumnHeader column={column} title={"State"} param="state" />
    ),
    cell: ({ row }) => {
      const { state } = getInvitationData(row);
      return <p className="font-semibold">{state}</p>;
    },
  },
  {
    accessorKey: "role",
    header: () => <div className="text-left">Role</div>,
    cell: ({ row }) => {
      const roleName =
        row.original.relationships?.role?.attributes?.name || "No Role";
      return <p className="font-semibold">{roleName}</p>;
    },
  },
  {
    accessorKey: "inserted_at",
    header: ({ column }) => (
      <DataTableColumnHeader
        column={column}
        title={"Inserted At"}
        param="inserted_at"
      />
    ),
    cell: ({ row }) => {
      const { inserted_at } = getInvitationData(row);
      return <DateWithTime dateTime={inserted_at} showTime={false} />;
    },
  },

  {
    accessorKey: "expires_at",
    header: ({ column }) => (
      <DataTableColumnHeader
        column={column}
        title={"Expires At"}
        param="expires_at"
      />
    ),
    cell: ({ row }) => {
      const { expires_at } = getInvitationData(row);
      return <DateWithTime dateTime={expires_at} showTime={false} />;
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
