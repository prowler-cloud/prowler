import { Spacer } from "@nextui-org/react";
import { Suspense } from "react";

import { getProvider } from "@/actions";
import {
  AddProviderModal,
  ColumnsProvider,
  DataTable,
  SkeletonTableProvider,
} from "@/components/providers";
import { Header } from "@/components/ui";

export default async function Providers() {
  return (
    <>
      <Header title="Providers" icon="fluent:cloud-sync-24-regular" />
      <Spacer />
      <div className="flex flex-col items-end w-full">
        <div className="flex space-x-6">
          <AddProviderModal />
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
  return <DataTable columns={ColumnsProvider} data={providers?.data ?? []} />;
};
