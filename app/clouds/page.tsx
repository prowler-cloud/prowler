"use client";

import useSWR from "swr";

import {
  Table,
  TableHeader,
  TableBody,
  TableColumn,
  TableRow,
  TableCell,
} from "@nextui-org/table";
import { fetcher } from "@/utils/fetcher";
import { title } from "@/components/primitives";

export default function CloudsPage() {
  const { data, error } = useSWR(
    `http://localhost:8080/api/v1/providers/aws/accounts`,
    fetcher,
  );

  // TODO FIX TYPE CHECKING
  const rowItems = data?.map((row: any) => (
    <TableRow key={row.id}>
      <TableCell>{row.account_id}</TableCell>
      <TableCell>{row.alias}</TableCell>
      <TableCell>{row.connected ? "True" : "False"}</TableCell>
    </TableRow>
  ));

  return (
    <div>
      <h1 className={title()}>Cloud Accounts</h1>
      <p className="mt-10 text-left">
        {error && <span className="text-red-400">Failed to load</span>}
        {!data && <span className="text-yellow-400">Loading</span>}
      </p>
      {data && (
        <Table aria-label="cloud accounts table" className="text-left mt-10">
          <TableHeader>
            <TableColumn>ACCOUNT ID</TableColumn>
            <TableColumn>ALIAS</TableColumn>
            <TableColumn>CONNECTED</TableColumn>
          </TableHeader>
          <TableBody>{rowItems}</TableBody>
        </Table>
      )}
      <p className="mt-24">This is a page with "use client", useSWR</p>
    </div>
  );
}
