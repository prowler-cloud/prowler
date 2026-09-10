"use client";

import { ColumnDef } from "@tanstack/react-table";

import { Badge } from "@/components/shadcn";
import { DateWithTime } from "@/components/shadcn/entities";
import { DataTableColumnHeader } from "@/components/shadcn/table";
import { isCloud } from "@/lib/shared/env";
import { UserProps } from "@/types";
import {
  USER_SIGN_IN_METHOD,
  type UserSignInMethod,
  type UserSignInMethodType,
} from "@/types/users";

import { DataTableRowActions } from "./data-table-row-actions";

const getUserData = (row: { original: UserProps }) => {
  return row.original.attributes;
};

type NonSamlSignInMethodType = Exclude<
  UserSignInMethodType,
  typeof USER_SIGN_IN_METHOD.SAML
>;

const SIGN_IN_METHOD_LABELS = {
  [USER_SIGN_IN_METHOD.EMAIL_PASSWORD]: "Email/password",
  [USER_SIGN_IN_METHOD.GOOGLE]: "Google",
  [USER_SIGN_IN_METHOD.GITHUB]: "GitHub",
  [USER_SIGN_IN_METHOD.PARTNER_SSO]: "Partner SSO",
} as const satisfies Record<NonSamlSignInMethodType, string>;

const getSignInMethodLabel = (signInMethod: UserSignInMethod) => {
  if (signInMethod.method === USER_SIGN_IN_METHOD.SAML) {
    return signInMethod.domain ? `SAML (${signInMethod.domain})` : "SAML";
  }

  return SIGN_IN_METHOD_LABELS[signInMethod.method];
};

export const getColumnsUser = (
  isCloudEnvironment: boolean,
): ColumnDef<UserProps>[] => [
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
    header: ({ column }) => (
      <DataTableColumnHeader column={column} title="Role" />
    ),
    cell: ({ row }) => {
      const { role } = getUserData(row);
      return <p className="font-semibold">{role?.name || "No Role"}</p>;
    },
    enableSorting: false,
  },
  ...(isCloudEnvironment
    ? [
        {
          id: "sign_in_methods",
          header: ({ column }) => (
            <DataTableColumnHeader column={column} title="Sign-In Methods" />
          ),
          cell: ({ row }) => {
            const { sign_in_methods: signInMethods } = getUserData(row);

            if (!signInMethods?.length) {
              return <span>-</span>;
            }

            return (
              <ul aria-label="Sign-in methods" className="flex flex-wrap gap-1">
                {signInMethods.map((signInMethod) => (
                  <li
                    key={`${signInMethod.method}:${signInMethod.domain ?? ""}`}
                  >
                    <Badge variant="tag">
                      {getSignInMethodLabel(signInMethod)}
                    </Badge>
                  </li>
                ))}
              </ul>
            );
          },
          enableSorting: false,
          enableColumnFilter: false,
        } satisfies ColumnDef<UserProps>,
      ]
    : []),
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
    header: () => null,
    id: "actions",
    cell: ({ row }) => {
      const roles = row.original.roles;
      return <DataTableRowActions row={row} roles={roles} />;
    },
    enableSorting: false,
  },
];

export const ColumnsUser = getColumnsUser(isCloud());
