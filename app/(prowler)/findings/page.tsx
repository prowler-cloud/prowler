import { Spacer } from "@nextui-org/react";
import React, { Suspense } from "react";

import { SkeletonTableFindings } from "@/components/findings";
import { Header } from "@/components/ui";

export default async function Findings() {
  return (
    <>
      <Header title="Findings" icon="ph:list-checks-duotone" />
      <Spacer />
      <div className="flex w-full flex-col items-start overflow-hidden">
        <Spacer y={6} />
        <Suspense fallback={<SkeletonTableFindings />}></Suspense>
      </div>
    </>
  );
}
