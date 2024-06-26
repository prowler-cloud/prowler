"use client";

import useSWR from "swr";
import React from "react";

import {
  Table,
  TableHeader,
  TableBody,
  TableColumn,
  TableRow,
  TableCell,
  User,
  Chip,
  Tooltip,
  getKeyValue,
} from "@nextui-org/react";
import { fetcher } from "@/utils/fetcher";
import { title } from "@/components/primitives";

import { PencilSquareIcon } from "@heroicons/react/24/solid";
import { TrashIcon } from "@heroicons/react/24/solid";
import { EyeIcon } from "@heroicons/react/24/solid";

const statusColorMap = {
  active: "success",
  paused: "danger",
  vacation: "warning",
};

const columns = [
  { name: "NAME", uid: "name" },
  { name: "ROLE", uid: "role" },
  { name: "STATUS", uid: "status" },
  { name: "ACTIONS", uid: "actions" },
];

const users = [
  {
    id: 1,
    name: "Tony Reichert",
    role: "CEO",
    team: "Management",
    status: "active",
    age: "29",
    avatar: "https://i.pravatar.cc/150?u=a042581f4e29026024d",
    email: "tony.reichert@example.com",
  },
  {
    id: 2,
    name: "Zoey Lang",
    role: "Technical Lead",
    team: "Development",
    status: "paused",
    age: "25",
    avatar: "https://i.pravatar.cc/150?u=a042581f4e29026704d",
    email: "zoey.lang@example.com",
  },
  {
    id: 3,
    name: "Jane Fisher",
    role: "Senior Developer",
    team: "Development",
    status: "active",
    age: "22",
    avatar: "https://i.pravatar.cc/150?u=a04258114e29026702d",
    email: "jane.fisher@example.com",
  },
  {
    id: 4,
    name: "William Howard",
    role: "Community Manager",
    team: "Marketing",
    status: "vacation",
    age: "28",
    avatar: "https://i.pravatar.cc/150?u=a048581f4e29026701d",
    email: "william.howard@example.com",
  },
  {
    id: 5,
    name: "Kristen Copper",
    role: "Sales Manager",
    team: "Sales",
    status: "active",
    age: "24",
    avatar: "https://i.pravatar.cc/150?u=a092581d4ef9026700d",
    email: "kristen.cooper@example.com",
  },
];

export default function CloudsPage() {
  const getAccounts = useSWR(
    `http://localhost:8080/api/v1/providers/aws/accounts`,
    fetcher,
  );

  const getAudits = useSWR(
    `http://localhost:8080/api/v1/providers/aws/audits`,
    fetcher,
  );

  // TODO FIX TYPE CHECKING
  const getScanDetails = (account_id: Number, detail: String) => {
    const scan =
      getAudits.data &&
      getAudits.data.find((audit: any) => audit.account_id === account_id);

    if (detail === "status") {
      return scan?.audit_complete && "Completed";
    }

    if (detail === "duration") {
      return scan?.audit_duration;
    }

    if (detail === "added") {
      return new Date(scan?.inserted_at).toString();
    }

    return;
  };

  // console.log("### getAccounts data", getAccounts.data);
  // console.log("### getAudits data", getAudits.data);

  // TODO FIX TYPE CHECKING
  const rowItems = getAccounts.data?.map((row: any) => (
    <TableRow key={row.id}>
      <TableCell>{row.account_id}</TableCell>
      <TableCell>{row.provider_id}</TableCell>
      <TableCell>TBD</TableCell>
      <TableCell>TBD</TableCell>
      <TableCell>{row.groups.map(String).join(", ")}</TableCell>
      <TableCell>{getScanDetails(row.account_id, "status")}</TableCell>
      <TableCell>{getScanDetails(row.account_id, "duration")}</TableCell>
      <TableCell>TBD</TableCell>
      <TableCell>{row.resources}</TableCell>
      <TableCell>{getScanDetails(row.account_id, "added")}</TableCell>
    </TableRow>
  ));

  // console.log("### rows", rows);

  // const rows = data;

  // const rows = [
  //   {
  //     key: "1",
  //     name: "Tony Reichert",
  //     role: "CEO",
  //     status: "Active",
  //   },
  //   {
  //     key: "2",
  //     name: "Zoey Lang",
  //     role: "Technical Lead",
  //     status: "Paused",
  //   },
  //   {
  //     key: "3",
  //     name: "Jane Fisher",
  //     role: "Senior Developer",
  //     status: "Active",
  //   },
  //   {
  //     key: "4",
  //     name: "William Howard",
  //     role: "Community Manager",
  //     status: "Vacation",
  //   },
  // ];

  // const columns = [
  //   {
  //     key: "provider_id",
  //     label: "Account",
  //   },
  //   {
  //     key: "groups",
  //     label: "Group(s)",
  //   },
  //   {
  //     key: "status",
  //     label: "Scan Status",
  //   },
  //   {
  //     key: "lastScan",
  //     label: "Last Scan",
  //   },
  //   {
  //     key: "nextScan",
  //     label: "Next Scan",
  //   },
  //   {
  //     key: "resources",
  //     label: "Resources",
  //   },
  //   {
  //     key: "added",
  //     label: "Added",
  //   },
  // ];

  const renderCell = React.useCallback((user, columnKey) => {
    const cellValue = user[columnKey];

    switch (columnKey) {
      case "name":
        return (
          <User
            avatarProps={{ radius: "lg", src: user.avatar }}
            description={user.email}
            name={cellValue}
          >
            {user.email}
          </User>
        );
      case "role":
        return (
          <div className="flex flex-col">
            <p className="text-bold text-sm capitalize">{cellValue}</p>
            <p className="text-bold text-sm capitalize text-default-400">
              {user.team}
            </p>
          </div>
        );
      case "status":
        return (
          <Chip
            className="capitalize"
            color={statusColorMap[user.status]}
            size="sm"
            variant="flat"
          >
            {cellValue}
          </Chip>
        );
      case "actions":
        return (
          <div className="relative flex items-center gap-2">
            <Tooltip content="Details">
              <span className="text-lg text-default-400 cursor-pointer active:opacity-50">
                <EyeIcon className="w-5 h-5" />
              </span>
            </Tooltip>
            <Tooltip content="Edit user">
              <span className="text-lg text-default-400 cursor-pointer active:opacity-50">
                <PencilSquareIcon className="w-5 h-5" />
              </span>
            </Tooltip>
            <Tooltip color="danger" content="Delete user">
              <span className="text-lg text-danger cursor-pointer active:opacity-50">
                <TrashIcon className="w-5 h-5" />
              </span>
            </Tooltip>
          </div>
        );
      default:
        return cellValue;
    }
  }, []);

  return (
    <div>
      <h1 className={title()}>Cloud Accounts</h1>
      <p className="mt-10 text-left">
        {getAccounts.error && (
          <span className="text-red-400">Failed to load</span>
        )}
        {getAccounts.isLoading && (
          <span className="text-yellow-400">Loading</span>
        )}
      </p>
      {getAccounts.data && (
        <Table aria-label="cloud accounts table" className="text-left mt-10">
          <TableHeader>
            <TableColumn>ACCOUNT ID</TableColumn>
            <TableColumn>PROVIDER ID</TableColumn>
            <TableColumn>ALIAS</TableColumn>
            <TableColumn>CONNECTED</TableColumn>
            <TableColumn>GROUP(S)</TableColumn>
            <TableColumn>SCAN STATUS</TableColumn>
            <TableColumn>LAST SCAN</TableColumn>
            <TableColumn>NEXT SCAN</TableColumn>
            <TableColumn>RESOURCES</TableColumn>
            <TableColumn>ADDED</TableColumn>
          </TableHeader>
          <TableBody>{rowItems}</TableBody>
        </Table>

        // <Table
        //   isStriped
        //   aria-label="cloud accounts table"
        //   className="text-left mt-10"
        // >
        //   <TableHeader columns={columns}>
        //     {(column) => (
        //       <TableColumn
        //         key={column.uid}
        //         align={column.uid === "actions" ? "center" : "start"}
        //       >
        //         {column.name}
        //       </TableColumn>
        //     )}
        //   </TableHeader>
        //   <TableBody items={users}>
        //     {(item) => (
        //       <TableRow key={item.id}>
        //         {(columnKey) => (
        //           <TableCell>{renderCell(item, columnKey)}</TableCell>
        //         )}
        //       </TableRow>
        //     )}
        //   </TableBody>
        // </Table>
      )}
      <p className="mt-24">This is a page with "use client", useSWR</p>
    </div>
  );
}
