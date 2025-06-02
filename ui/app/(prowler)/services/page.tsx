import { Spacer } from "@nextui-org/react";

import { FilterControls } from "@/components/filters";

export default async function Services() {
  // const searchParamsKey = JSON.stringify(searchParams || {});
  return (
    <>
      <Spacer y={4} />
      <FilterControls />
      <Spacer y={4} />
      {/* <Suspense key={searchParamsKey} fallback={<ServiceSkeletonGrid />}>
        <SSRServiceGrid />
      </Suspense> */}
    </>
  );
}
