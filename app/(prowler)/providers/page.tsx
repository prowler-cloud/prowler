import { Spacer } from "@nextui-org/react";
import React from "react";

import { CustomTable, Header, ModalWrap } from "@/components";

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
  const onSave = async () => {
    "use server";
    // event we want to pass down, ex. console.log("### hello");
  };

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
      <ModalWrap
        modalTitle="Modal Title"
        modalBody={
          <>
            <p>Modal body content</p>
          </>
        }
        actionButtonLabel="Save"
        onAction={onSave}
        openButtonLabel="Open Modal"
      />
    </>
  );
}
