import { Spacer } from "@nextui-org/react";
import { redirect } from "next/navigation";
import { Suspense } from "react";

import { getProvider } from "@/actions";
import {
  AddProviderModal,
  ColumnsProvider,
  DataTableProvider,
  SkeletonTableProvider,
} from "@/components/providers";
import { Header } from "@/components/ui";

export default async function Providers({
  searchParams,
}: {
  searchParams?: {
    query?: string;
    page: string;
  };
}) {
  return (
    <>
      <Header title="Providers" icon="fluent:cloud-sync-24-regular" />
      <Spacer y={4} />
      <div className="flex flex-col items-end w-full">
        <div className="flex space-x-6">
          <AddProviderModal />
        </div>
        <Spacer y={6} />
        <Suspense key={searchParams?.page} fallback={<SkeletonTableProvider />}>
          <SSRDataTable searchParams={searchParams} />
        </Suspense>
      </div>
    </>
  );
}

const SSRDataTable = async ({
  searchParams,
}: {
  searchParams?: {
    query?: string;
    page?: string;
    sort?: string;
    filter?: string;
  };
}) => {
  const query = searchParams?.query || "";
  const page = searchParams?.page ? parseInt(searchParams.page) : 1;
  const sort = searchParams?.sort || "";
  const filter = searchParams?.filter || "";

  const providersData = await getProvider({ query, page, sort, filter });
  const [providers] = await Promise.all([providersData]);

  if (providers?.errors) redirect("/providers");

  return (
    <DataTableProvider
      columns={ColumnsProvider}
      data={providers?.data ?? []}
      metadata={providers?.meta}
    />
  );
};
