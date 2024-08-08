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
import { Header, Pagination } from "@/components/ui";

export default async function Providers({
  searchParams,
}: {
  searchParams: {
    page: number;
  };
}) {
  console.log({ searchParams }, "los searchParamsss!");
  return (
    <>
      <Header title="Providers" icon="fluent:cloud-sync-24-regular" />
      <Spacer />
      <div className="flex flex-col items-end w-full">
        <div className="flex space-x-6">
          <AddProviderModal />
        </div>
        <Spacer y={6} />
        <Suspense key={searchParams.page} fallback={<SkeletonTableProvider />}>
          <SSRDataTable searchParams={searchParams} />
        </Suspense>
      </div>
    </>
  );
}

const SSRDataTable = async ({
  searchParams,
}: {
  searchParams: {
    page: number;
  };
}) => {
  // const perPage = searchParams['per_page'] ?? '5'
  // const page = searchParams.page ? parseInt(searchParams.page) : 1;
  const providersData = await getProvider({});
  // const [providers] = await Promise.all([providersData]);
  // const { providerDetails, currentPage, totalPages, totalItems } = providersData;
  // console.log(currentPage, totalPages, 'hehe')
  // if (providers.meta.pagination.count === 0) {
  //   redirect('/');
  // }
  // console.log(providers);
  // const currentPage = providers.meta.pagination.page;
  // const pages = providers.meta.pagination.pages;
  // const count = providers.meta.pagination.count;

  // console.log(`Pages: ${pages}, Count: ${count}`);
  return (
    <>
      {/* <DataTableProvider columns={ColumnsProvider} data={providerDetails ?? []} /> */}
      {/* <Pagination totalPages={totalPages} currentPage={currentPage} /> */}
    </>
  );
};
