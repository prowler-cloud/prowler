import { FilterControls } from "@/components/filters";
import { ContentLayout } from "@/components/ui";

export default async function Services() {
  // const searchParamsKey = JSON.stringify(searchParams || {});
  return (
    <ContentLayout
      title="Services"
      icon="material-symbols:linked-services-outline"
    >
      <div className="h-4" />
      <FilterControls />
      <div className="h-4" />
      {/* <Suspense key={searchParamsKey} fallback={<ServiceSkeletonGrid />}>
        <SSRServiceGrid />
      </Suspense> */}
    </ContentLayout>
  );
}
