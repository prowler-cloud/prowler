import { Spacer } from "@nextui-org/react";
import React from "react";

import { ColumnsProviders, DataTable, Header, ModalWrap } from "@/components";
import { getProvider } from "@/lib/actions";

export default async function Providers() {
  const providers = await getProvider();
  const onSave = async () => {
    "use server";
    // event we want to pass down, ex. console.log("### hello");
  };

  return (
    <>
      <Header title="Providers" icon="fluent:cloud-sync-24-regular" />
      <Spacer />
      <div className="flex flex-col items-end w-full">
        <ModalWrap
          modalTitle="Modal Title"
          modalBody={
            <>
              <p>Modal body content</p>
            </>
          }
          actionButtonLabel="Save"
          onAction={onSave}
          openButtonLabel="Add Cloud Accounts"
        />
        <Spacer y={6} />
        <DataTable columns={ColumnsProviders} data={providers.providers.data} />
      </div>
    </>
  );
}
