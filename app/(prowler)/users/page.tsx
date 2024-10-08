import { Spacer } from "@nextui-org/react";
import { redirect } from "next/navigation";
import { Suspense } from "react";

import { getUsers } from "@/actions/users";
// import { auth } from "@/auth.config";
import { Header } from "@/components/ui";
import {
  AddUserModal,
  ColumnsUser,
  DataTableUser,
  SkeletonTableUser,
} from "@/components/users";
import { SearchParamsProps } from "@/types";

export default async function Users({
  searchParams,
}: {
  searchParams: SearchParamsProps;
}) {
  const searchParamsKey = JSON.stringify(searchParams || {});

  return (
    <>
      <Header title="User Management" icon="ci:users" />
      <Spacer y={4} />
      <div className="flex w-full flex-col items-end">
        <div className="flex space-x-6">
          <AddUserModal />
        </div>
        <Spacer y={6} />
        <Suspense key={searchParamsKey} fallback={<SkeletonTableUser />}>
          <SSRDataTable searchParams={searchParams} />
        </Suspense>
      </div>
    </>
  );
}

const SSRDataTable = async ({
  searchParams,
}: {
  searchParams: SearchParamsProps;
}) => {
  const page = parseInt(searchParams.page?.toString() || "1", 10);
  const usersData = await getUsers({ page });
  const [users] = await Promise.all([usersData]);

  if (users?.errors) redirect("/users");

  return (
    <DataTableUser
      columns={ColumnsUser}
      data={users?.users?.data ?? []}
      metadata={users?.meta}
    />
  );
};
