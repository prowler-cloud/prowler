"use client";

import { ColumnDef } from "@tanstack/react-table";

import { DateWithTime } from "@/components/ui/entities";
import { UserActions } from "@/components/users";
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
    accessorKey: "actions",
    header: () => <div className="text-right">Actions</div>,
    id: "actions",
    cell: ({ row }) => {
      const userData = getUserData(row);
      return <UserActions userData={userData} />;
    },
  },
];
