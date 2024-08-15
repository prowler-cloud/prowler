import { Spacer } from "@nextui-org/react";
import { redirect } from "next/navigation";
import { Suspense } from "react";

import { getService } from "@/actions/services";
import { FilterControls } from "@/components/filters";
import { ServiceCard, ServiceSkeletonGrid } from "@/components/services";
import { Header } from "@/components/ui";
import { searchParamsProps } from "@/types";

export default async function Services({ searchParams }: searchParamsProps) {
  return (
    <>
      <Header
        title="Services"
        icon="material-symbols:linked-services-outline"
      />
      <Spacer y={4} />
      <FilterControls />
      <Spacer y={4} />
      <Suspense key={searchParams.page} fallback={<ServiceSkeletonGrid />}>
        <SSRServiceGrid searchParams={searchParams} />
      </Suspense>
    </>
  );
}

const SSRServiceGrid = async ({ searchParams }: searchParamsProps) => {
  const page = searchParams.page ? parseInt(searchParams.page) : 1;
  const servicesData = await getService({ page });
  const [services] = await Promise.all([servicesData]);

  if (services?.errors) redirect("/services");

  return (
    <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-3 xl:grid-cols-4 3xl:grid-cols-5">
      {services.services?.data.map((service: any) => (
        <ServiceCard
          key={service.id}
          fidingsFailed={service.attributes.findings.failed}
          serviceAlias={service.attributes.alias}
        />
      ))}
    </div>
  );
};
