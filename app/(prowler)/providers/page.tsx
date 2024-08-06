import { Spacer } from "@nextui-org/react";
import React, { Suspense } from "react";

import { getProvider } from "@/actions";
import {
  AddProvider,
  ColumnsProviders,
  DataTable,
  Header,
  ModalWrap,
  SkeletonTableProvider,
} from "@/components";

export default async function Providers() {
  const onSave = async () => {
    "use server";
    // event we want to pass down, ex. console.log("### hello");
  };

  return (
    <>
      <Header title="Providers" icon="fluent:cloud-sync-24-regular" />
      <Spacer />
      <div className="flex flex-col items-end w-full">
        <div className="flex space-x-6">
          <AddProvider />
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
        </div>
        <Spacer y={6} />
        <Suspense fallback={<SkeletonTableProvider />}>
          <SSRDataTable />
        </Suspense>
      </div>
    </>
  );
}

const SSRDataTable = async () => {
  const providersData = await getProvider();
  const [providers] = await Promise.all([providersData]);
  return <DataTable columns={ColumnsProviders} data={providers?.data ?? []} />;
};
