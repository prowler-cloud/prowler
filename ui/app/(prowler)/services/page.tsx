import { Spacer } from "@nextui-org/react";

import { FilterControls } from "@/components/filters";
import { ContentLayout } from "@/components/ui";

export default async function Services() {
  // const searchParamsKey = JSON.stringify(searchParams || {});
  return (
    <ContentLayout
      title="Services"
      icon="material-symbols:linked-services-outline"
    >
      <Spacer y={4} />
      <FilterControls />
      <Spacer y={4} />
      {/* <Suspense key={searchParamsKey} fallback={<ServiceSkeletonGrid />}>
        <SSRServiceGrid />
      </Suspense> */}
    </ContentLayout>
  );
}
