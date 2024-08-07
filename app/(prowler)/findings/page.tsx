import { Spacer } from "@nextui-org/react";
import React, { Suspense } from "react";

import { ColumnsFindings, SkeletonTableFindings } from "@/components";
import { DataTableProvider } from "@/components/providers";
import { Header } from "@/components/ui";

export default async function Findings() {
  return (
    <>
      <Header title="Findings" icon="ph:list-checks-duotone" />
      <Spacer />
      <div className="flex flex-col items-end w-full">
        <Spacer y={6} />
        <Suspense fallback={<SkeletonTableFindings />}>
          <SSRDataTable />
        </Suspense>
      </div>
    </>
  );
}

const SSRDataTable = async () => {
  return (
    <DataTableProvider
      columns={ColumnsFindings}
      data={[
        {
          id: "12345",
          attributes: {
            CheckTitle:
              "Ensure users of groups with AdministratorAccess policy have MFA tokens enabled",
            severity: "high",
            status: "fail",
            region: "us-west-2",
            service: "cloudformation",
            account: "dev (106908755756)",
          },
        },
        {
          id: "67891",
          attributes: {
            CheckTitle: "Find secrets in CloudFormation outputs",
            severity: "low",
            status: "success",
            region: "us-east-1",
            service: "cloudformation",
            account: "stg (987654321987)",
          },
        },
      ]}
    />
  );
};
