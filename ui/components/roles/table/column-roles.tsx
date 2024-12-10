"use client";

import { ColumnDef } from "@tanstack/react-table";

import { DateWithTime } from "@/components/ui/entities";
import { DataTableColumnHeader } from "@/components/ui/table";
import { RolesProps } from "@/types";

const getRoleAttributes = (row: { original: RolesProps["data"][number] }) => {
  return row.original.attributes;
};

const getRoleRelationships = (row: {
  original: RolesProps["data"][number];
}) => {
  return row.original.relationships;
};

export const ColumnsRoles: ColumnDef<RolesProps["data"][number]>[] = [
  {
    accessorKey: "role",
    header: ({ column }) => (
      <DataTableColumnHeader column={column} title={"Role"} param="name" />
    ),
    cell: ({ row }) => {
      const data = getRoleAttributes(row);
      return (
        <p className="font-semibold">
          {data.name[0].toUpperCase() + data.name.slice(1).toLowerCase()}
        </p>
      );
    },
  },
  {
    accessorKey: "users",
    header: ({ column }) => (
      <DataTableColumnHeader column={column} title={"Users"} param="users" />
    ),
    cell: ({ row }) => {
      const relationships = getRoleRelationships(row);
      const count = relationships.users.meta.count;
      return (
        <p className="font-semibold">
          {count === 0
            ? "No Users"
            : `${count} ${count === 1 ? "User" : "Users"}`}
        </p>
      );
    },
  },
  {
    accessorKey: "invitations",
    header: ({ column }) => (
      <DataTableColumnHeader
        column={column}
        title={"Invitations"}
        param="invitations"
      />
    ),
    cell: ({ row }) => {
      const relationships = getRoleRelationships(row);
      return (
        <p className="font-semibold">
          {relationships.invitations.meta.count === 0
            ? "No Invitations"
            : `${relationships.invitations.meta.count} ${
                relationships.invitations.meta.count === 1
                  ? "Invitation"
                  : "Invitations"
              }`}
        </p>
      );
    },
  },
  // {
  //   accessorKey: "updated_at",
  //   header: ({ column }) => (
  //     <DataTableColumnHeader
  //       column={column}
  //       title={"Updated At"}
  //       param="updated_at"
  //     />
  //   ),
  //   cell: ({ row }) => {
  //     const { updated_at } = getRoleAttributes(row);
  //     return <DateWithTime dateTime={updated_at} showTime={false} />;
  //   },
  // },
  {
    accessorKey: "inserted_at",
    header: ({ column }) => (
      <DataTableColumnHeader
        column={column}
        title={"Added At"}
        param="inserted_at"
      />
    ),
    cell: ({ row }) => {
      const { inserted_at } = getRoleAttributes(row);
      return <DateWithTime dateTime={inserted_at} showTime={false} />;
    },
  },
];
