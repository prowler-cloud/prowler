import { Spacer } from "@nextui-org/react";
import { redirect } from "next/navigation";
import { Suspense } from "react";

import { getUsers } from "@/actions/users";
import { Header } from "@/components/ui";
import {
  ColumnsUser,
  DataTableUser,
  SkeletonTableUser,
} from "@/components/users";
import { searchParamsProps } from "@/types";

export default async function Users({ searchParams }: searchParamsProps) {
  return (
    <>
      <Header title="User Management" icon="ci:users" />
      <Spacer y={4} />
      <div className="flex flex-col items-end w-full">
        <Spacer y={6} />
        <Suspense key={searchParams.page} fallback={<SkeletonTableUser />}>
          <SSRDataTable searchParams={searchParams} />
        </Suspense>
      </div>
    </>
  );
}

const SSRDataTable = async ({ searchParams }: searchParamsProps) => {
  const page = searchParams.page ? parseInt(searchParams.page) : 1;
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
