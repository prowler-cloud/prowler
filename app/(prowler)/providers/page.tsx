import { Spacer } from "@nextui-org/react";
import React from "react";

import { CustomTable, Header } from "@/components";

const visibleColumns: string[] = [
  "account",
  "group",
  "scan_status",
  "last_scan",
  "next_scan",
  "resources",
  "added",
  "actions",
];

export default function Providers() {
  return (
    <>
      <Header title="Providers" icon="fluent:cloud-sync-24-regular" />
      <Spacer />
      <CustomTable
        initialVisibleColumns={visibleColumns}
        initialRowsPerPage={10}
        selectionMode={"none"}
      />
      <Spacer />
    </>
  );
}
