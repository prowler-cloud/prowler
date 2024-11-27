import { Spacer } from "@nextui-org/react";
import { Suspense } from "react";

import { getServices } from "@/actions/services";
import { FilterControls } from "@/components/filters";
import { ServiceCard, ServiceSkeletonGrid } from "@/components/services";
import { Header } from "@/components/ui";
import { SearchParamsProps } from "@/types";

export default async function Services({
  searchParams,
}: {
  searchParams: SearchParamsProps;
}) {
  const searchParamsKey = JSON.stringify(searchParams || {});
  return (
    <>
      <Header
        title="Services"
        icon="material-symbols:linked-services-outline"
      />
      <Spacer y={4} />
      <FilterControls />
      <Spacer y={4} />
      <Suspense key={searchParamsKey} fallback={<ServiceSkeletonGrid />}>
        <SSRServiceGrid searchParams={searchParams} />
      </Suspense>
    </>
  );
}

const SSRServiceGrid = async ({
  searchParams,
}: {
  searchParams: SearchParamsProps;
}) => {
  const servicesData = await getServices(searchParams);
  const [services] = await Promise.all([servicesData]);

  return (
    <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-3 xl:grid-cols-4">
      {services?.map((service: any) => (
        <ServiceCard
          key={service.service_id}
          fidingsFailed={service.fail_findings}
          serviceAlias={service.service_alias}
        />
      ))}
    </div>
  );
};
