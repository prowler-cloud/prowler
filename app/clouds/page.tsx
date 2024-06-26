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
      return new Date(scan?.inserted_at).toDateString();
    }

    return;
  };

  // console.log("### getAccounts data", getAccounts.data);
  // console.log("### getAudits data", getAudits.data);

  // TODO FIX TYPE CHECKING
  const rowItems = getAccounts.data?.map((row: any) => (
    <TableRow key={row.id}>
      <TableCell>{row.aws_account_id}</TableCell>
      <TableCell>{row.provider_id}</TableCell>
      <TableCell>{row.alias}</TableCell>
      <TableCell>{row.connected && "Connected"}</TableCell>
      <TableCell>{row.groups.map(String).join(", ")}</TableCell>
      <TableCell>{getScanDetails(row.account_id, "status")}</TableCell>
      <TableCell>{getScanDetails(row.account_id, "duration")}</TableCell>
      <TableCell>TBD</TableCell>
      <TableCell>{row.resources}</TableCell>
      <TableCell>{getScanDetails(row.account_id, "added")}</TableCell>
    </TableRow>
  ));

  // TODO IMPLEMENT NEXT UI SPECIFIC TABLE COMPONENT WITH VARIED RENDERING

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
      )}
      <p className="mt-24">This is a page with "use client", useSWR</p>
    </div>
  );
}
